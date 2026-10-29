"""The leave checks of the evidence disposition (ATLAS_EVIDENCE_DISPOSITION):
one function, used by the triage reply and by the analyst's
coverage.set_evidence_disposition, decides whether an item or a class may
be left unread. A leave names one closed kind and its proof; code checks
the proof. Nothing else (a question answered, time, effort) leaves
evidence.

- outside_window: the unit's data ends before the window starts. A memory
  image is never outside (it is acquired after the fact and holds what
  ran). The window start is the earliest stated start, including starts
  held as "stated by a noted claim", and the brief's earliest stated date.
- other_scope: the item's host is named by no current finding or work item
  and shares no account (a profile folder few hosts hold, or the export
  rows of a named host) with a host that is. The sweep reads listing paths
  and tabular exports; the content of files no call extracted is outside
  it, and the result says so.
- duplicate_of: the same content hash, or for images the same volumes with
  the same listing (file count and total size).
- unreadable: two failed calls of readers that take the unit's format, or
  no registered reader declares that format.
- unrelated_content: no registered reader parses any of the unit's
  classes.
Any leave is refused while the sweep finds a current attacker entity in
the unit's listing or exports.
"""
from __future__ import annotations

from core.store_lock import locked as _locked

import os
import re
from contextlib import closing
from pathlib import Path
from typing import Any, Optional

KINDS = ("outside_window", "other_scope", "duplicate_of", "unreadable", "unrelated_content", "unlikely_to_help",
         "empty", "no_reader")
# Kinds only code states (a fact of the evidence, recomputed by the pass
# that makes it): the writer refuses them from the model.
CODE_KINDS = ("empty", "no_reader")
# The phrases that state the forbidden ground of a leave (a leave rests
# on an observation from a read on the same host, never on a question
# being answered or a report being due): whole phrases at word
# boundaries, so "the printer in question", "spooler report",
# "insufficient quota" or "write cache not required for a volume" are
# observations ("not needed for the ..." names a purpose, not a fact; a
# bare "not needed" is a NON_REASON). The rule's own vocabulary.
FORBIDDEN_GROUND_RE = re.compile(
    r"(?i)(?<![\w-])(?:task-\d{4}(?:/[ps]\d+)?|[ps]\d+ (?:is|was) answered|answered|the question|for the report|"
    r"not (?:needed|required) for (?:the|this|that|these|those|any|our|answering)|enough evidence|"
    r"already covered|superseded by)(?![\w-])")
# The reason field never holds a non-reason: a lexical list of the
# non-answers a model writes when it has none (not an artefact list).
NON_REASONS = frozenset({"no reason", "none", "n/a", "na", "not relevant", "not needed", "irrelevant",
                         "see above", "as above", "not required", "skip", "skipped", "unknown", "tbd"})
MIN_REASON_CHARS = 20
SWEEP_BLIND = ("the sweep reads listing paths and tabular exports; the content of files no call has "
               "extracted is outside it")
# A profile folder this share of the listed hosts holds is the platform's
# own (a default or public profile), never an account two hosts share.
COMMON_SHARE = 0.10
_PROFILE_RE = re.compile(r"(?i)^(?:[^/]+/)?(?:users|home|documents and settings)/([^/]+)/")


# ── units ────────────────────────────────────────────────────────────────

_DASHES = "\u2014\u2013\u2012\u2010-"


def label_handle(label: str) -> str:
    """A class label as a model types it: the head before the dash that
    opens its gloss, dash variants and spacing folded, case folded."""
    text = str(label or "")
    for d in _DASHES:
        text = text.replace(f" {d} ", " \u2014 ")
    head = text.split(" \u2014 ", 1)[0]
    return " ".join(head.replace("\u2014", "-").split()).casefold()


def find_unit(ledger: dict[str, Any], ref: str) -> tuple[str, Optional[dict[str, Any]]]:
    """("item" | "class", unit) for an item path or id, or a class id."""
    ref = str(ref or "").strip()
    classes = ledger.get("classes") or {}
    if ref in classes:
        return "class", classes[ref]
    for iid, item in (ledger.get("items") or {}).items():
        if isinstance(item, dict) and ref in (iid, item.get("path")):
            return "item", item
    return "", None


def classes_by_handle(ledger: dict[str, Any], ref: str, hosts: list[str] | None = None) -> list[dict[str, Any]]:
    """The class units a label handle names (label_handle: the head before
    the dash, dashes and spaces folded), on ``hosts`` when given; "" or a
    class id names nothing here (find_unit does). A handle written as
    "<host>: <label>" names that host's class."""
    text = str(ref or "").strip()
    if not text or text in (ledger.get("classes") or {}):
        return []
    want_hosts = {str(h).casefold() for h in (hosts or []) if str(h).strip()}
    if ":" in text and not want_hosts:
        head, _sep, tail = text.partition(":")
        if tail.strip():
            want_hosts, text = {head.strip().casefold()}, tail.strip()
    handle = label_handle(text)
    from core.evidence_depth import unit_host
    items = ledger.get("items") or {}
    out = []
    for c in (ledger.get("classes") or {}).values():
        if not isinstance(c, dict) or label_handle(c.get("label")) != handle:
            continue
        # A host is matched as the block names it: the host, else the
        # item's file name (unit_host), so "usb-a.dd (1)" copied back finds
        # the class.
        if want_hosts and unit_host(c, items).casefold() not in want_hosts:
            continue
        out.append(c)
    return out


def handle_candidates(ledger: dict[str, Any], ref: str) -> list[str]:
    """The distinct label handles that start with the words of ``ref``: the
    names to offer when a handle names nothing."""
    words = label_handle(ref).split()
    if not words:
        return []
    seen = []
    for c in (ledger.get("classes") or {}).values():
        if not isinstance(c, dict):
            continue
        h = label_handle(c.get("label"))
        if all(w in h for w in words) and h not in seen:
            seen.append(h)
    return seen[:8]


def _item_of(ledger: dict[str, Any], level: str, unit: dict[str, Any]) -> dict[str, Any]:
    return unit if level == "item" else (ledger.get("items") or {}).get(unit.get("item")) or {}


def _classes_of(ledger: dict[str, Any], level: str, unit: dict[str, Any]) -> list[dict[str, Any]]:
    if level == "class":
        return [unit]
    return [c for c in (ledger.get("classes") or {}).values() if isinstance(c, dict) and c.get("item") == unit["id"]]


def _index(case_dir):
    from core.contents_index import _connect
    return _connect(case_dir)


def _entries_where(level: str, unit: dict[str, Any], item: dict[str, Any]) -> tuple[str, list]:
    """The SQL filter of the unit's live listing entries."""
    where = "origin = 'image' AND image = ? AND is_dir = 0 AND deleted = 0 AND version_of IS NULL"
    args: list = [item.get("path")]
    if level == "class":
        where += " AND (class = ? OR class = ?)"
        args += [unit["label"], unit["label"] + " (appears empty)"]
    return where, args


# ── the window ───────────────────────────────────────────────────────────

def window_start(case_dir) -> str:
    """The earliest stated start: every host start, every start held as
    stated by a noted claim, and the brief's earliest stated date."""
    from core.claim_graph import load_graph
    from core.incident_window import _iso, incident_window
    w = incident_window(load_graph(case_dir), case_dir=case_dir)
    starts = [v[0][0] for v in w["hosts"].values()] + [v[0][0] for v in w["accounts"].values()]
    starts += [t for _k, _v, t, _c in w.get("noted") or []]
    try:
        from core.question_plan import _DATE_RE, _narrative
        for _h, body in _narrative(str(case_dir)):
            for m in _DATE_RE.finditer(body):
                iso = _iso(m.group(0))
                if iso:
                    starts.append(iso)
    except Exception:  # noqa: BLE001
        pass
    return min(starts) if starts else ""


def data_end(case_dir, level: str, unit: dict[str, Any], item: dict[str, Any]) -> str:
    """The latest moment the unit's data shows: an image's (or class's)
    newest listed entry, a log file's last record from its survey; "" when
    not known."""
    from core.incident_window import _iso
    if item.get("kind") == "image":
        con = _index(case_dir)
        if con is None:
            return ""
        where, args = _entries_where(level, unit, item)
        with closing(con):
            row = con.execute(f"SELECT MAX(mtime) FROM entries WHERE {where}", args).fetchone()
        return _iso(row[0]) if row and row[0] else ""
    try:
        from core.evidence_survey import _load
        text = str((_load(case_dir).get(item.get("id")) or {}).get("text") or "")
    except Exception:  # noqa: BLE001
        text = ""
    m = re.search(r"last (?:record at|line:) ?(\S+ ?\S*)", text)
    return _iso(m.group(1)) if m else ""


# ── the sweep ────────────────────────────────────────────────────────────

# {case: (what the set is read from, the set)}: the attacker set is read
# by every leave check and every leave written; within a turn the beliefs
# (claim_graph.json) and the trace do not change, so one read serves the
# turn (the incident map derives from those two and rewrites its store on
# every read, so its file is no signal). One entry per case.
_ATTACKER_MEMO: dict[str, tuple[tuple, list[str]]] = {}


def _attacker_key(case_dir) -> tuple:
    root = Path(case_dir)

    def stat(p: Path) -> tuple:
        try:
            st = p.stat()
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return ()
    try:
        from core.execution_log import log
        n = len(log._entries) if str(log.case_dir() or "") == str(root.resolve()) else -1
    except Exception:  # noqa: BLE001
        n = -1
    return (stat(root / ".atlas" / "claim_graph.json"), n)


def attacker_entities(case_dir) -> list[str]:
    """The values current beliefs type as the attacker's: the incident
    map's attacker entities when the map is on (one attacker set for the
    map and disposition), else the typed rows. Read once per change of the
    beliefs, the map or the trace (_ATTACKER_MEMO)."""
    root = str(Path(case_dir).resolve())
    key = _attacker_key(case_dir)
    hit = _ATTACKER_MEMO.get(root)
    if hit is not None and hit[0] == key:
        return list(hit[1])
    out = _attacker_entities(case_dir)
    if len(_ATTACKER_MEMO) > 16:
        _ATTACKER_MEMO.clear()
    _ATTACKER_MEMO[root] = (key, list(out))
    return out


def _attacker_entities(case_dir) -> list[str]:
    try:
        from core import incident_map
        m = incident_map.open(case_dir)
        if m is not None:
            return sorted({str(e["value"]) for e in m.attacker_entities(proposals=True)})
    except Exception:  # noqa: BLE001 - the typed rows still give the set
        pass
    from core.claim_graph import is_current_belief, load_graph
    out = []
    for n in (load_graph(case_dir).get("nodes") or {}).values():
        if isinstance(n, dict) and n.get("kind") in ("claim", "conclusion") and is_current_belief(n):
            out += [str(r.get("value")) for r in n.get("indicators") or []
                    if isinstance(r, dict) and r.get("side") == "attacker" and r.get("value")]
    return sorted(set(out))


def _host_exports(case_dir, host: str) -> list[str]:
    return [e for e, _n in exports_of_hosts(case_dir, [host])] if host else []


def exports_of_hosts(case_dir, hosts: list[str]) -> list[tuple[str, int]]:
    """The exports holding rows of any of ``hosts`` (the contents index's
    sources, by host), each with how many of those hosts it covers, the
    widest first. One query."""
    want = sorted({str(h).casefold() for h in hosts if h})
    con = _index(case_dir)
    if con is None or not want:
        return []
    marks = ",".join("?" * len(want))
    with closing(con):
        rows = con.execute(f"SELECT export, COUNT(DISTINCT lower(host)) FROM sources WHERE lower(host) IN ({marks}) "
                           "GROUP BY export ORDER BY 2 DESC, export", want).fetchall()
    return [(str(r[0]), int(r[1])) for r in rows if r[0]]


def _class_exports(case_dir, unit: dict[str, Any], item: dict[str, Any]) -> list[str]:
    """The exports holding rows of a member of this class (the index's
    sources, joined to the entries by image and class): a class is swept
    over what was parsed out of its own files, never over every export of
    its host. A whole export counts when any of its sources is a member;
    an export that mixes classes is counted for each."""
    con = _index(case_dir)
    if con is None:
        return []
    where, args = _entries_where("class", unit, item)
    with closing(con):
        rows = con.execute("SELECT DISTINCT export FROM sources WHERE entry_id IN "
                           f"(SELECT id FROM entries WHERE {where}) ORDER BY export", args).fetchall()
    return [str(r[0]) for r in rows if r[0]]


def unattributed_exports(case_dir) -> list[str]:
    """The exports none of whose sources the index ties to a host: what they
    cover cannot be told by host."""
    con = _index(case_dir)
    if con is None:
        return []
    with closing(con):
        rows = con.execute("SELECT export FROM sources GROUP BY export "
                           "HAVING SUM(CASE WHEN host IS NULL OR host = '' THEN 0 ELSE 1 END) = 0 "
                           "ORDER BY export").fetchall()
    return [str(r[0]) for r in rows if r[0]]


# The sweep's scans, each done once and shared: an image's entries are
# scanned once per value set and listing generation for every class of
# the image, and a host's exports are counted once per value set and
# export version for every class of the host (the attacker entities and
# the exports do not change within a turn; the key says when they did).
# Bounded: cleared whole when full.
_SWEEP_MEMO: dict[tuple, Any] = {}


def _memo(key: tuple, build):
    hit = _SWEEP_MEMO.get(key)
    if hit is not None:
        return hit
    if len(_SWEEP_MEMO) > 256:
        _SWEEP_MEMO.clear()
    value = build()
    _SWEEP_MEMO[key] = value
    return value


def _generation(case_dir) -> int:
    try:
        from core.contents_index import listing_generation
        return listing_generation(case_dir)
    except Exception:  # noqa: BLE001
        return 0


def _sources_version(case_dir) -> tuple:
    """(rows, highest id) of the index's sources table: it changes whenever
    an export is registered, which the listing generation (bumped by a
    listing alone) does not."""
    con = _index(case_dir)
    if con is None:
        return ()
    with closing(con):
        row = con.execute("SELECT COUNT(*), COALESCE(MAX(id), 0) FROM sources").fetchone()
    return (int(row[0]), int(row[1])) if row else ()


def _image_value_paths(case_dir, item: dict[str, Any], vals: list[str]) -> dict[str, dict[str, str]]:
    """{value: {class label: first live path of that class holding the
    value as a whole token, "": the first of any class}} over an image's
    live entries, one scan per value for the whole image."""
    from core.evidence_disposition import _label
    out: dict[str, dict[str, str]] = {}
    con = _index(case_dir)
    if con is None:
        return out
    where, args = _entries_where("item", {}, item)
    with closing(con):
        for v in vals:
            tail = v.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()
            # The value as a whole token of the path (any character that is
            # not a letter or a digit delimits it), so a short value does
            # not match inside longer names.
            token = re.compile(r"(?<![a-z0-9])" + re.escape(tail) + r"(?![a-z0-9])")
            per: dict[str, str] = {}
            for path, raw in con.execute(f"SELECT path, class FROM entries WHERE {where} AND lower(path) LIKE ?",
                                         [*args, f"%{tail}%"]):
                if not token.search(str(path).lower()):
                    continue
                per.setdefault("", str(path))
                per.setdefault(_label(raw)[0], str(path))
            out[v] = per
    return out


def _export_versions(case_dir, exports: list[str]) -> tuple:
    out = []
    for e in exports:
        try:
            st = os.stat(os.path.join(str(case_dir), e))
            out.append((e, st.st_mtime_ns, st.st_size))
        except OSError:
            out.append((e, 0, 0))
    return tuple(out)


def sweep(case_dir, level: str, unit: dict[str, Any], item: dict[str, Any], values: list[str]) -> list[str]:
    """Where the unit's listing paths or its host's exports hold one of
    ``values``: "<value> in <where>" lines. The scans are shared
    (_SWEEP_MEMO): the image's entries once per value set, the host's
    exports counted once per value set and export version; a class reads
    its own label's paths and its own exports out of them."""
    hits: list[str] = []
    vals = [v for v in values if len(v) >= 3]
    if not vals:
        return hits
    root = str(case_dir)
    if item.get("kind") == "image":
        found = _memo(("image", root, str(item.get("path") or ""), tuple(vals), _generation(case_dir)),
                      lambda: _image_value_paths(case_dir, item, vals))
        label = str(unit.get("label") or "") if level == "class" else ""
        for v in vals:
            path = (found.get(v) or {}).get(label)
            if path:
                hits.append(f"{v} in {item.get('path')}::{path}")
    host = str(item.get("host") or "")
    if level == "class" and item.get("kind") == "image":
        # Keyed by the sources table's version too: an export registered
        # mid-run (its rows may hold the value) must reach the next sweep.
        exports = _memo(("class_exports", root, str(item.get("path") or ""), str(unit.get("label") or ""),
                         _generation(case_dir), _sources_version(case_dir)),
                        lambda: _class_exports(case_dir, unit, item))
    else:
        exports = _host_exports(case_dir, host)
    if exports:
        # One count over the host's exports (a class's own are among them),
        # read per class.
        universe = _host_exports(case_dir, host) if host else []
        if not set(exports) <= set(universe):
            universe = list(dict.fromkeys([*universe, *exports]))
        try:
            from tools.tabular import count_values
            counts = _memo(("counts", root, tuple(universe), tuple(vals), _export_versions(case_dir, universe)),
                           lambda: count_values(root, vals, universe).get("counts") or {})
            for v, per in counts.items():
                for src in exports:
                    c = (per or {}).get(src) or {}
                    if c.get("full") or c.get("name"):
                        hits.append(f"{v} in {src}")
        except Exception:  # noqa: BLE001
            pass
    return hits


# ── scope ────────────────────────────────────────────────────────────────

def _named_hosts(case_dir) -> set[str]:
    """Hosts a current finding or a work item names."""
    from core.claim_graph import is_current_belief, load_graph
    from core.forensic_citation import host_mentioned, known_case_hosts
    hosts = known_case_hosts(case_dir)
    named: set[str] = set()
    for n in (load_graph(case_dir).get("nodes") or {}).values():
        if isinstance(n, dict) and n.get("kind") in ("claim", "conclusion") and is_current_belief(n):
            if n.get("host"):
                named.add(str(n["host"]).casefold())
            named |= {h.casefold() for h in hosts if host_mentioned(h, str(n.get("statement") or ""))}
    try:
        from core.execution_log import log
        for wi in log.work_items():
            h = str((wi.get("target") or {}).get("host") or "")
            if h:
                named.add(h.casefold())
    except Exception:  # noqa: BLE001
        pass
    # The hosts the brief and the questions put in scope.
    texts = []
    try:
        texts.append((Path(case_dir) / "CASE.md").read_text(encoding="utf-8", errors="replace"))
    except OSError:
        pass
    try:
        from core.investigation_tasks import load_tasks
        texts += [str(t.get("text") or "") for t in load_tasks(str(case_dir)).get("tasks") or []
                  if isinstance(t, dict)]
    except Exception:  # noqa: BLE001
        pass
    blob = "\n".join(texts)
    named |= {h.casefold() for h in hosts if blob and host_mentioned(h, blob)}
    return named


_PROFILES_CACHE: dict[tuple, dict[str, set[str]]] = {}


def _profiles(case_dir) -> dict[str, set[str]]:
    """{host (casefold): profile folder names} from the listing, cached by
    the listing generation (one scan per new listing, not per check)."""
    try:
        from core.contents_index import db_path, listing_generation
        key = (str(db_path(case_dir).resolve()), listing_generation(case_dir))
    except Exception:  # noqa: BLE001
        key = None
    if key is not None and key in _PROFILES_CACHE:
        return _PROFILES_CACHE[key]
    found = _scan_profiles(case_dir)
    if key is not None:
        _PROFILES_CACHE.clear()
        _PROFILES_CACHE[key] = found
    return found


def _scan_profiles(case_dir) -> dict[str, set[str]]:
    con = _index(case_dir)
    if con is None:
        return {}
    out: dict[str, set[str]] = {}
    with closing(con):
        for host, path in con.execute("SELECT host, path FROM entries WHERE origin = 'image' "
                                      "AND host IS NOT NULL AND host != ''"):
            m = _PROFILE_RE.match(str(path))
            if m:
                out.setdefault(str(host).casefold(), set()).add(m.group(1).casefold())
    return out


def _own_accounts(profiles: dict[str, set[str]], host: str) -> set[str]:
    """A host's profile accounts that are not common to the estate (held
    by at most COMMON_SHARE of the listed hosts, plus one)."""
    import math
    limit = max(1, math.ceil(COMMON_SHARE * len(profiles)))
    holders: dict[str, int] = {}
    for names in profiles.values():
        for p in names:
            holders[p] = holders.get(p, 0) + 1
    return {p for p in profiles.get(host, set()) if holders.get(p, 0) <= limit + 1}


def scope_facts(case_dir, item: dict[str, Any]) -> list[str]:
    """The facts the scope and sweep checks read for an item, as lines for
    the triage: whether its host is in scope, the accounts it shares with
    hosts in scope, its accounts in their exports, and the current attacker
    values found in it. The same inputs the checks use, so a model sees
    what a leave will be held to."""
    out: list[str] = []
    host = str(item.get("host") or "")
    named = _named_hosts(case_dir)
    if not host:
        out.append("its host: not in the Evidence Links")
    elif host.casefold() in named:
        out.append(f"its host {host} is in scope")
    else:
        profiles = _profiles(case_dir)
        own = _own_accounts(profiles, host.casefold()) if profiles else set()
        shared = sorted({p for other in named for p in own & profiles.get(other, set())})
        out.append(f"accounts its host shares with hosts in scope: {len(shared)}"
                   + (f" ({', '.join(shared[:5])})" if shared else ""))
        exports = [e for h in named for e in _host_exports(case_dir, h)]
        seen: list[str] = []
        if own and exports:
            try:
                from tools.tabular import count_values
                counts = count_values(str(case_dir), sorted(own), exports,
                                      {a: "account" for a in own}).get("counts") or {}
                seen = sorted(a for a, per in counts.items() if any((c or {}).get("full") for c in (per or {}).values()))
            except Exception:  # noqa: BLE001
                seen = []
        out.append(f"its accounts in the exports of hosts in scope: {len(seen)}"
                   + (f" ({', '.join(seen[:5])})" if seen else ""))
    try:
        hits = sweep(case_dir, "item", item, item, attacker_entities(case_dir))
    except Exception:  # noqa: BLE001
        hits = []
    out.append(f"current attacker values found in it: {len(hits)}" + (f" ({'; '.join(hits[:3])})" if hits else ""))
    return out


def _scope_check(case_dir, item: dict[str, Any], ctx: dict[str, Any] | None = None) -> str:
    """"" when the item may be other_scope, else why not. ``ctx``: inputs a
    reopen pass computed once for every unit (named hosts, the accounts the
    named hosts' exports show)."""
    host = str(item.get("host") or "").casefold()
    if not host:
        return "the item has no host in the Evidence Links, so its scope cannot be checked"
    named = (ctx or {}).get("named") if ctx and "named" in ctx else _named_hosts(case_dir)
    if host in named:
        return f"its host {item.get('host')} is named by a current finding or a work item"
    profiles = _profiles(case_dir)
    if profiles:
        own = _own_accounts(profiles, host)
        for other in named:
            shared = own & profiles.get(other, set())
            if shared:
                return f"it shares the account {sorted(shared)[0]} with {other.upper()}, a host in scope"
        if ctx is not None and "accounts_in_exports" in ctx:
            hit = sorted(own & ctx["accounts_in_exports"])
            if hit:
                return f"its account {hit[0]} appears in the exports of a host in scope"
            return ""
        named_exports = [e for h in named for e in _host_exports(case_dir, h)]
        if own and named_exports:
            try:
                from tools.tabular import count_values
                counts = count_values(str(case_dir), sorted(own), named_exports,
                                      {a: "account" for a in own}).get("counts") or {}
                for acct, per in counts.items():
                    if any((c or {}).get("full") for c in (per or {}).values()):
                        return f"its account {acct} appears in the exports of a host in scope"
            except Exception:  # noqa: BLE001
                pass
    return ""


# ── duplicates and readers ───────────────────────────────────────────────

def _duplicate(case_dir, item: dict[str, Any], other: dict[str, Any]) -> str:
    """"" when ``other`` holds the same content, else why not."""
    if not other or other.get("id") == item.get("id"):
        return "duplicate_of names no other item of the case"
    try:
        from core.hash_index import _load
        idx = _load(str(case_dir))
        shas = {sha for sha, rows in idx.items()
                if any(isinstance(r, dict) and r.get("path") == item.get("path") for r in rows)}
        if any(any(isinstance(r, dict) and r.get("path") == other.get("path") for r in idx.get(sha, []))
               for sha in shas):
            return ""
    except Exception:  # noqa: BLE001
        pass
    if item.get("kind") == "image" and other.get("kind") == "image":
        con = _index(case_dir)
        if con is not None:
            from core.contents_index import _meta_get
            with closing(con):
                a, b = (_meta_get(con, f"image:{x.get('path')}") for x in (item, other))
                shape = [con.execute("SELECT COUNT(*), SUM(size) FROM entries WHERE origin = 'image' AND image = ?",
                                     (x.get("path"),)).fetchone() for x in (item, other)]
            if a.get("volumes") and a.get("volumes") == b.get("volumes") and tuple(shape[0]) == tuple(shape[1]):
                return ""
    return "no equal content hash, and the images' volumes and listings differ"


def unit_format(case_dir, level: str, unit: dict[str, Any], item: dict[str, Any]) -> str:
    """The input format of a unit: an image or memory item's kind, else the
    commonest extension of its files."""
    if level == "item" and item.get("kind") in ("image", "memory", "capture", "archive"):
        return str(item["kind"])
    con = _index(case_dir)
    if con is None or item.get("kind") != "image":
        p = str(item.get("path") or "")
        return p.rsplit(".", 1)[-1].lower() if "." in p.rsplit("/", 1)[-1] else ""
    where, args = _entries_where(level, unit, item)
    counts: dict[str, int] = {}
    with closing(con):
        for (name,) in con.execute(f"SELECT name FROM entries WHERE {where}", args):
            ext = str(name).rsplit(".", 1)[-1].lower() if "." in str(name) else ""
            if ext:
                counts[ext] = counts.get(ext, 0) + 1
    return max(counts.items(), key=lambda kv: kv[1])[0] if counts else ""


def _format_declared(fmt: str, heads: dict[str, list[str]] | None = None) -> bool:
    """Whether the reader table declares a format: a label's head, a media
    type an extension names (tools.media_types.EXTENSIONS) or a text
    format. An extension outside all three is unknown, never "no reader"."""
    from core.artifact_value import TEXT_FORMATS
    from tools.media_types import EXTENSIONS
    if not fmt:
        return False
    if heads is None:
        from tools.tool_capabilities import readers_by_format, registered_tool_schemas
        heads = _label_heads(readers_by_format(registered_tool_schemas()))
    return fmt in heads or bool(EXTENSIONS.get(fmt)) or fmt in TEXT_FORMATS


def _label_heads(table: dict[str, list[str]]) -> dict[str, list[str]]:
    """{head: readers} of the reader table's parameter-declared labels: the
    label before its gloss, whole ("evtx" and "evtx (folder)" are the evtx
    readers, "evtx csv" is its own), and its singular, every label of a
    head accumulated (never one overwriting another)."""
    from tools.tool_capabilities import is_media_label
    heads: dict[str, list[str]] = {}
    for label, tools in table.items():
        if is_media_label(label):
            continue
        head = label.split(" (", 1)[0].strip().lower()
        if not head:
            continue
        for key in {head, head.rstrip("s")}:
            heads.setdefault(key, []).extend(tools)
    return heads


def unit_readers(case_dir, level: str, unit: dict[str, Any], item: dict[str, Any],
                 whole: bool = False) -> tuple[list[str], bool]:
    """(readers, known) of a unit. An item: the readers of its format
    (readers_for) and of its name (a reader that declares the name,
    tools.tool_capabilities.readers_by_input_name). A content class of an
    image: per member name, the readers that declare the name, else the
    readers of its extension (the table's labels by their head, the media
    type the extension names, the text tools for a text format), among
    which a reader that declares names is never reached by an extension (it
    said what it reads: a thumbnail cache's ``.db`` is no SQLite store).
    ``known``: every member's format is one the readers declare (a name a
    reader declares, or an extension the table names); a member with an
    extension the table never names, or an extensionless name no reader
    declares, makes the class unknown, and an unknown format is never "no
    reader" nor costed as hard. ``whole``: every member name of the class
    (one SELECT of the distinct names), as a code leave must rest on; else
    the sample the class unit carries, or the first 500 names."""
    if not (level == "class" and item.get("kind") == "image"):
        from tools.tool_capabilities import readers_by_input_name
        fmt = unit_format(case_dir, level, unit, item)      # the class route reads member names, never this
        readers = list(readers_for(fmt))
        if level == "item":
            readers += readers_by_input_name(str(item.get("path") or ""))
        known = fmt in _OPENED_KINDS or bool(readers) or _format_declared(fmt)
        return list(dict.fromkeys(readers)), known
    names = set() if whole else {str(n).lower() for n in (unit.get("names") or [])}
    if not names:
        con = _index(case_dir)
        if con is not None:
            where, args = _entries_where(level, unit, item)
            limit = "" if whole else " LIMIT 500"
            with closing(con):
                names = {str(n).rsplit("/", 1)[-1].lower() for (n,) in
                         con.execute(f"SELECT DISTINCT name FROM entries WHERE {where}{limit}", args)}
    if not names:
        return [], False
    from core.artifact_value import TEXT_FORMATS
    from tools.media_types import EXTENSIONS
    from tools.tool_capabilities import (_media_readers, input_name_declarations, readers_by_format,
                                         readers_by_input_name, registered_tool_schemas, text_readers)
    try:
        tools = registered_tool_schemas()
        table, decl = readers_by_format(tools), input_name_declarations(tools)
    except Exception:  # noqa: BLE001
        tools, table, decl = [], {}, []
    heads = _label_heads(table)
    declaring = {r for r, _pats in decl}
    text = text_readers(tools) if tools else []
    readers: list[str] = []
    known = True
    for name in sorted(names):
        by_name = readers_by_input_name(name, decl)
        if by_name:
            readers += by_name                      # a name a reader declares
            continue
        ext = name.rsplit(".", 1)[-1] if "." in name[1:] else ""
        media = EXTENSIONS.get(ext, "") if ext else ""
        if not ext or not (ext in heads or media or ext in TEXT_FORMATS):
            known = False                           # no channel declares it
            continue
        readers += [r for r in heads.get(ext, []) if r not in declaring]
        if media:
            readers += [r for r in _media_readers([media], table, tools) if r not in declaring]
        if ext in TEXT_FORMATS:
            readers += text                         # plain text is read by the text tools
    return list(dict.fromkeys(readers)), known


def readers_for(fmt: str) -> list[str]:
    """The registered readers whose declared input format is ``fmt`` (an
    extension or a kind): by a parameter-declared format's name, and by the
    media type the extension names (tools.tool_capabilities
    .declared_readers_for_extension)."""
    if not fmt:
        return []
    from core.artifact_value import TEXT_FORMATS
    from tools.tool_capabilities import (declared_readers_for_extension, is_media_label, readers_by_format,
                                         registered_tool_schemas, text_readers)
    out = []
    for label, tools in readers_by_format(registered_tool_schemas()).items():
        if is_media_label(label):
            continue
        head = label.split(" (")[0].split()[0].lower()
        if head == fmt or head.rstrip("s") == fmt:
            out += tools
    out += declared_readers_for_extension(fmt)
    if fmt in TEXT_FORMATS:
        out += text_readers()            # plain text is read by the text tools
    return list(dict.fromkeys(out))


# Item kinds Atlas opens itself (filesystem, memory and capture readers):
# "no reader declares the format" never holds for them.
_OPENED_KINDS = {"image": "", "memory": "", "capture": "pcap", "archive": ""}
# The namespaces whose tools open an item of each kind Atlas opens itself
# (the filesystem readers and the image mount tools for an image, the memory framework for a
# memory image, the archive tools for an archive): wiring of the tool
# namespaces, so a strings pass or a parser of another format failing on an
# item never makes it unreadable.
_OPENING_NAMESPACES = {"image": ("tsk", "ewf", "img"), "memory": ("vol",), "archive": ("archive",)}


def _unreadable(case_dir, level: str, unit: dict[str, Any], item: dict[str, Any], proof: list[int],
                by_code: bool = False) -> str:
    opened = level == "item" and item.get("kind") in _OPENED_KINDS
    if opened:
        fmt, readers, known = _OPENED_KINDS.get(item.get("kind"), ""), readers_for(_OPENED_KINDS.get(item.get("kind"), "")), True
    else:
        fmt = unit_format(case_dir, level, unit, item)
        readers, known = unit_readers(case_dir, level, unit, item)
    if not readers and not opened:
        if not known:
            # An unknown format says nothing about readers: the clause
            # that no reader declares it never holds for it.
            return ("the format of this unit is not known (its files carry no extension a reader declares), so "
                    "no reader can be said to lack; read it, or cite two failed reads of it")
        if not by_code:
            # A known format no reader declares is code's fact (no_reader,
            # set by the credit pass), never a model's unreadable leave.
            return ("no registered reader declares its format: Atlas records that itself as no_reader; cite two "
                    "failed reads of it for unreadable, or leave it to the code")
        return ""                                       # no registered reader declares the format
    from core.coverage_ledger import failed_read_attempt
    from core.execution_log import log
    by = log.index().by_call_id or {}
    failed = set()
    for cid in proof:
        e = by.get(int(cid))
        # A call a gate refused, one with invalid arguments, an expected
        # nonzero exit or a host fault tried nothing: it is no failed read.
        if not isinstance(e, dict) or e.get("type") != "tool_call" or not failed_read_attempt(e):
            continue
        tool = (str(e.get("cmd") or "").removeprefix("<py>:").split() or [""])[0]
        dotted = {tool, tool.replace("_", ".", 1)}
        takes = (dotted & set(readers) or any(tool.endswith(r.split(".", 1)[-1]) for r in readers)
                 or (opened and not readers
                     and tool.replace(".", "_").split("_", 1)[0] in _OPENING_NAMESPACES.get(item.get("kind"), ())))
        if takes:
            if str(item.get("path") or "").rsplit("/", 1)[-1] in str(e.get("cmd") or "") + str(e.get("args") or ""):
                failed.add(int(cid))
    if len(failed) >= 2:
        return ""
    who = (f"readers that take it ({', '.join(readers[:6])})" if readers else
           f"tools that open it ({', '.join(_OPENING_NAMESPACES.get(item.get('kind'), ()))})")
    return f"unreadable needs two failed calls on this {fmt or item.get('kind') or 'unit'} by {who}; " \
           f"the proof holds {len(failed)}"


# ── the check ────────────────────────────────────────────────────────────

def check_leave(case_dir: str | os.PathLike, ledger: dict[str, Any], ref: str, kind: str, reason: str,
                proof: list | None = None, ignore_entities: frozenset | set = frozenset(),
                ctx: dict[str, Any] | None = None, by_code: bool = False) -> dict[str, Any]:
    """{"ok": True, "note"} when the unit may be left by ``kind`` with this
    proof, else {"ok": False, "error"}. ``proof``: call ids, or for
    duplicate_of the other item's path. ``by_code``: the leave is a code
    fact (CODE_KINDS are only accepted so). An unreadable unit is left even
    where the sweep hits: the hit goes into the note for a person."""
    level, unit = find_unit(ledger, ref)
    if unit is None:
        return {"ok": False, "error": f"{ref!r} is no evidence item or class of this case"}
    if kind not in KINDS:
        return {"ok": False, "error": (f"a unit is left by one of {', '.join(k for k in KINDS if k not in CODE_KINDS)}; "
                                       f"{kind!r} is not one")}
    if kind in CODE_KINDS and not by_code:
        return {"ok": False, "error": f"{kind!r} is a fact code states from the evidence, never a stated reason"}
    bad = non_reason(ledger, unit, reason)
    if bad:
        return {"ok": False, "error": bad}
    item = _item_of(ledger, level, unit)
    proof = list(proof or [])
    # The attacker set once per pass where a pass hands it in (ctx), else
    # the case's current one.
    entities = ctx["attacker"] if ctx and "attacker" in ctx else attacker_entities(case_dir)
    hits = sweep(case_dir, level, unit, item, [e for e in entities if e not in ignore_entities])
    if hits and kind != "unreadable":
        return {"ok": False, "error": ("the sweep finds a current attacker entity here: " + "; ".join(hits[:3])
                                       + "; read it")}
    why = ""
    if kind == "unlikely_to_help":
        why = _unlikely_to_help(case_dir, level, unit, item, reason, proof)
    elif kind == "no_reader":
        readers, known = unit_readers(case_dir, level, unit, item, whole=True)
        why = "" if known and not readers else "a reader declares its format, or its format is not known"
    elif kind == "empty":
        why = _empty(case_dir, level, unit, item)
    elif kind == "outside_window":
        if item.get("kind") == "memory":
            why = "a memory image holds what ran when it was taken and is never outside the window"
        else:
            start = (ctx or {}).get("window") if ctx and "window" in ctx else window_start(case_dir)
            end = data_end(case_dir, level, unit, item)
            if not start:
                why = "no belief or brief states when the incident started"
            elif not end:
                why = "when this unit's data ends is not known"
            elif end >= start:
                why = f"its data runs to {end}, after the window's earliest start {start}"
    elif kind == "other_scope":
        why = _scope_check(case_dir, item, ctx)
    elif kind == "duplicate_of":
        other = find_unit(ledger, str(proof[0]) if proof else "")[1] or {}
        why = _duplicate(case_dir, item, other)
    elif kind == "unreadable":
        why = _unreadable(case_dir, level, unit, item, proof_call_ids(proof)[0], by_code=by_code)
    elif kind == "unrelated_content":
        own = _classes_of(ledger, level, unit)
        parsed = [c["label"] for c in own if unit_readers(case_dir, "class", c, item)[0]]
        if not own:
            why = "it has no content classes, so nothing shows its content is unrelated"
        elif item.get("kind") == "memory":
            why = "the memory readers parse the structures a memory image holds"
        elif parsed:
            why = f"registered readers parse its classes ({', '.join(parsed[:4])})"
    if why:
        return {"ok": False, "error": f"{ref} cannot be left as {kind}: {why}"}
    note = SWEEP_BLIND if kind in ("other_scope", "outside_window") else ""
    if hits:
        # An unreadable unit cannot be decided by the model: it is left,
        # and what its listing holds is written where a person reads it.
        note = "its listing holds " + "; ".join(hits[:3]) + ": a person must look"
    return {"ok": True, "level": level, "id": unit["id"], "note": note}


def non_reason(ledger: dict[str, Any], unit: dict[str, Any], reason: str) -> str:
    """Why ``reason`` is no reason: empty, shorter than MIN_REASON_CHARS, or
    a non-answer (NON_REASONS). "" when it may be stored. The same words on
    another host are not refused here: each host's leave rests on that
    host's own proof read (_unlikely_to_help), which is the check that
    tells an observation from a paste."""
    text = " ".join(str(reason or "").split())
    folded = text.casefold().strip(" .!")
    if not folded:
        return "a leave needs a reason in words beside its kind"
    if folded in NON_REASONS or len(text) < MIN_REASON_CHARS:
        return (f"a leave needs a reason of at least {MIN_REASON_CHARS} characters saying why this evidence "
                "cannot help; a word such as 'not needed' or 'n/a' is no reason")
    return ""


_TASK_REF_RE = re.compile(r"(?i)\btask-\d{4}(?:/[ps]\d+)?\b")
# The forms a model writes a call id in: the number alone, or behind a
# "call" word (with "id"), a "#" or a "c", joined by a space, a dash or an
# underscore ("5", "call 5", "call-5", "call_5", "#5", "c5", "call id 5");
# the "c" form takes no leading zero, since "C0010" is a belief id's shape.
# A lexical shape, universal, never a case's.
_PROOF_ID_RE = re.compile(r"(?i)^(?:(?:#|call(?:[ _-]?id)?)?[ _-]*(\d+)|c[ _-]*([1-9]\d*))$")
_BELIEF_ID_RE = re.compile(r"(?i)^c0\d+$")
# Atlas's own hint writes "call 5 (misc_evtx_filter)": every parenthesised
# part is dropped before matching; one string may cite several ids,
# joined by commas or "and".
_PROOF_TAIL_RE = re.compile(r"\s*\([^)]*\)")
_PROOF_SPLIT_RE = re.compile(r"(?i)\s*,\s*|\s+and\s+")


def proof_call_ids(proof: list | None) -> tuple[list[int], list[str]]:
    """(the call ids a proof cites, the tokens that are no call id): a
    number as such, or a string in one of the forms _PROOF_ID_RE names,
    its parenthesised parts and trailing punctuation dropped, several per
    string when joined by commas or "and"."""
    ids: list[int] = []
    bad: list[str] = []
    for p in proof or []:
        if isinstance(p, bool):
            bad.append(str(p))
            continue
        if isinstance(p, int):
            ids.append(int(p))
            continue
        text = _PROOF_TAIL_RE.sub("", str(p)).strip(" ,.;:")
        for tok in (t for t in _PROOF_SPLIT_RE.split(text) if t.strip()) if text else [str(p)]:
            m = _PROOF_ID_RE.match(tok.strip(" ,.;:"))
            if m:
                ids.append(int(m.group(1) or m.group(2)))
            else:
                bad.append(tok)
    return ids, bad


def _proof_token_why(tok: str) -> str:
    """Why a proof token is no call id: a belief id's shape, or no shape."""
    return "is a belief id, not a call number" if _BELIEF_ID_RE.match(tok.strip()) else "is no call number"
# A bare number of up to three digits in a reason is a count or a type code
# ("type 10", "0 logons"), never an investigative handle to trace.
_BARE_NUMBER_RE = re.compile(r"^\d{1,3}$")
# A name that is a date or a clock, as core.entities.names_in writes them:
# the only kind of value the case's own statements may ground.
_TEMPORAL_RE = re.compile(r"^\d{4}-\d{2}-\d{2}|^\d{1,2}:\d{2}")


def _case_statements(case_dir) -> list[str]:
    """The case's own statements of time a leave may restate without a read
    showing them: the brief (CASE.md), the task texts, and the run's
    computed incident window (the starts the current beliefs anchor, the
    earliest stated start). They ground dates and times only: an address,
    an account, a file or a hash the brief names is a value a read must
    show ("no sign of the brief's indicator" rests on a read that looked)."""
    out: list[str] = []
    try:
        from core.investigation_tasks import load_tasks, read_case_markdown
        out.append(read_case_markdown(case_dir))
        for t in load_tasks(case_dir).get("tasks") or []:
            if isinstance(t, dict):
                out.append(str(t.get("text") or ""))
                out += [str(p.get("text") or "") for p in (t.get("parts") or []) if isinstance(p, dict)]
    except Exception:  # noqa: BLE001 - no brief or tasks to read
        pass
    try:
        from core.claim_graph import load_graph
        from core.incident_window import incident_window
        w = incident_window(load_graph(case_dir), case_dir=case_dir)
        out += [t for v in list(w.get("hosts", {}).values()) + list(w.get("accounts", {}).values()) for t, _c in v]
        if w.get("estate"):
            out.append(str(w["estate"][0]))
        out.append(window_start(case_dir))
    except Exception:  # noqa: BLE001 - no beliefs: the brief alone states the window
        pass
    return [s for s in out if s]


def _unlikely_to_help(case_dir, level: str, unit: dict[str, Any], item: dict[str, Any], reason: str,
                      proof: list) -> str:
    """Why an unlikely_to_help leave does not hold. The leave rests on an
    observation: the reason names a fact seen in a read on the same host
    (never a question being answered, FORBIDDEN_GROUND), the proof cites
    that read (a successful content read on this host; a listing is no
    read), and every value the reason names is grounded: an indicator (an
    address, a domain, an account, a hash, a file name or path) by that
    read's printed rows, its command or its arguments only (the composed
    answer's grounding check, core.entities.unstated), a date or a time
    also by the case's own statements (_case_statements: the brief, the
    task texts, the computed incident window), a host name of the case
    (core.forensic_citation.known_case_hosts) by itself, and a bare number
    under four digits being a count or a type code, not a value; an
    observation of absence names what the rows do not show. A reason with
    no checkable value must name the read's own source. The refusal names
    the missing piece and the qualifying reads on this host, so a small
    model copies one."""
    if FORBIDDEN_GROUND_RE.search(str(reason or "")):
        return ("the reason rests on a question or a report, which is never why evidence cannot help; name "
                "a fact seen in a read on this host (for example what the host's security log shows in the window) "
                "and cite that read")
    ids, bad = proof_call_ids(proof)
    host = str(item.get("host") or "").casefold()
    from core.coverage_ledger import _entry_tool, reads_content, resolved_entry
    from core.execution_log import log
    by = log.index().by_call_id or {}
    reads: list[dict] = []
    lacking: list[str] = []
    if bad:
        # A token that is no call number: told the form, with a real call
        # number of this host's reads to write.
        example = next(iter(_qualifying_read_ids(case_dir, host, by, 1)), None)
        lacking.append("; ".join(f"{b[:40]!r} {_proof_token_why(b)}" for b in bad[:3])
                       + f" (proof ids are call numbers, write {example[0] if example else 'the call number'})")
    for cid in ids:
        e = by.get(cid) or by.get(str(cid))
        if not isinstance(e, dict) or e.get("type") != "tool_call":
            lacking.append(f"call {cid} is not in this run's trace")
            continue
        e = resolved_entry(case_dir, e)
        if e is None or e.get("success") is not True or not reads_content(_entry_tool(e)):
            lacking.append(f"call {cid} is no successful content read")
            continue
        if host:
            where = _call_host(case_dir, e)
            if where != host:
                # A read whose paths name no host of the case (or two) is no
                # host's own read: it proves a leave on none.
                lacking.append(f"call {cid} read another host's evidence" if where else
                               f"call {cid} names no host of the case in its paths (or two), so it is no read "
                               f"of {item.get('host')}'s own evidence")
                continue
        reads.append(e)
    if not reads:
        hint = _qualifying_reads(case_dir, host, by)
        return ("proof must cite a successful content read on this host that shows the observation ("
                + ("; ".join(lacking[:4]) if lacking else "none cited") + ")"
                + (f"; reads on this host: {hint}" if hint else ""))
    # The reason's names against the proof reads' printed rows, the call's
    # command line and its arguments (a filter with no match states what
    # it looked for in its request, not in its rows).
    import json as _json
    from core.entities import NamePool, names_in, unstated
    from core.indicators import rows_text
    texts = [rows_text(e) for e in reads] + [str(e.get("cmd") or "") for e in reads]
    for e in reads:
        args = e.get("args")
        texts.append(args if isinstance(args, str) else _json.dumps(args, ensure_ascii=False, default=str)
                     if args else "")
    try:
        from core.answer_synthesis import case_name_lexicon
        from core.claim_graph import load_graph
        lex = case_name_lexicon(load_graph(case_dir))
    except Exception:  # noqa: BLE001
        lex = frozenset()
    try:
        from core.forensic_citation import known_case_hosts
        hosts = {h.casefold() for h in known_case_hosts(case_dir)}
    except Exception:  # noqa: BLE001
        hosts = set()
    if host:
        hosts.add(host)
    lex = frozenset(lex) | hosts                    # a host name stays one name, never its pieces
    reads_pool = NamePool.from_texts(texts)
    case_pool = NamePool.from_texts(_case_statements(case_dir))
    missing = []
    for m in unstated(str(reason or ""), reads_pool, lex):
        value = m.split("=")[-1]
        if _BARE_NUMBER_RE.fullmatch(value) or value.casefold() in hosts:
            continue                                # a count or a type code; a host of the case
        if _TEMPORAL_RE.match(value) and case_pool.covers(m):
            continue                                # a date or a time the case states
        missing.append(m)
    if missing:
        return ("the reason names " + ", ".join(m.split("=")[-1] for m in missing[:6])
                + ", which the cited reads' rows, command and arguments do not show (a date or a time may also "
                "stand in the brief, the task texts or the incident window; a host of the case stands by itself); "
                "name what the read showed, or cite the read that shows these")
    if not names_in(str(reason or ""), lex):
        # A reason with no checkable value rests on the read it cites: it
        # names that read's source (a file name its call carries).
        sources = _read_sources(reads)
        low = str(reason or "").casefold()
        if sources and not any(src.casefold() in low for src in sources):
            return ("the reason names no value the cited reads show, so it must name the read's source it rests "
                    "on (" + ", ".join(sources[:4]) + ") and say what that source showed")
    return ""


def _read_sources(reads: list[dict]) -> list[str]:
    """The file names a read's command line and arguments carry: the last
    component of each path token, each side of an inner-path separator."""
    import json as _json
    from core.coverage_ledger import _blob_paths
    out: list[str] = []
    for e in reads:
        args = e.get("args")
        blob = str(e.get("cmd") or "") + " " + (args if isinstance(args, str) else
                                                 _json.dumps(args, ensure_ascii=False, default=str) if args else "")
        for p in _blob_paths(blob):
            for part in p.split("::"):
                base = part.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].strip("\"'")
                if base and base not in out:
                    out.append(base)
    return out


def _qualifying_read_ids(case_dir, host: str, by: dict, limit: int = 4) -> list[tuple[int, str]]:
    """The successful content reads on ``host`` a leave may cite, newest
    first, as (call id, tool)."""
    from core.coverage_ledger import _entry_tool, reads_content
    out: list[tuple[int, str]] = []
    for cid in sorted((int(k) for k in by if str(k).isdigit()), reverse=True):
        e = by.get(cid) or by.get(str(cid))
        if not isinstance(e, dict) or e.get("type") != "tool_call" or e.get("success") is not True:
            continue
        tool = _entry_tool(e)
        if not reads_content(tool) or (host and _call_host(case_dir, e) != host):
            continue
        out.append((cid, tool))
        if len(out) >= limit:
            break
    return out


def _qualifying_reads(case_dir, host: str, by: dict, limit: int = 4) -> str:
    """_qualifying_read_ids as "call N (tool), ..."."""
    return ", ".join(f"call {cid} ({tool})" for cid, tool in _qualifying_read_ids(case_dir, host, by, limit))


def _call_host(case_dir, entry: dict) -> str:
    """The case host a call's paths belong to (the Evidence Links, else the
    host label as a path token), casefolded; "" when its paths name none
    or name two."""
    from core.coverage_ledger import _blob_paths
    from core.evidence_links import host_of_path
    paths = set(_blob_paths(str(entry.get("cmd") or "")))
    args = entry.get("args")
    if isinstance(args, str):
        paths |= set(_blob_paths(args))
    elif isinstance(args, dict):
        for v in args.values():
            if isinstance(v, str):
                paths |= set(_blob_paths(v))
    found = {str(host_of_path(case_dir, p) or "").casefold() for p in paths}
    found.discard("")
    return next(iter(found)) if len(found) == 1 else ""


def _empty(case_dir, level: str, unit: dict[str, Any], item: dict[str, Any]) -> str:
    """Why an empty leave does not hold: a live member of the class does
    not appear empty in the index."""
    if level != "class" or item.get("kind") != "image":
        return "only a content class of an image is left as empty by the index"
    con = _index(case_dir)
    if con is None:
        return "the contents index is not here to say the class's files are empty"
    where, args = _entries_where(level, unit, item)
    with closing(con):
        rows = con.execute(f"SELECT class FROM entries WHERE {where}", args).fetchall()
    if not rows:
        return "the index lists no live file of this class"
    if any(not str(r[0] or "").endswith("(appears empty)") for r in rows):
        return "a live file of this class does not appear empty"
    return ""


@_locked
def set_disposition(case_dir: str | os.PathLike, ref: str, state: str, kind: str = "", reason: str = "",
                    proof: list | None = None, hosts: list[str] | None = None,
                    by_code: bool = False) -> dict[str, Any]:
    """Set a unit's disposition: relevant (to be read), or left only through
    check_leave. Read and partial are never stated: the evidence sets them
    (core.evidence_disposition.credit_dispositions). ``ref`` is an item
    path, a class id, or a class label handle (the head before the dash):
    a handle leaves that label on every host, or on ``hosts``, one check per
    host, and answers per host. Returns {"success", ...}."""
    from core.coverage_ledger import load_ledger, save_ledger
    ledger = load_ledger(case_dir)
    if state not in ("relevant", "left"):
        return {"success": False, "error": ("state is relevant or left; read and partial are set from the "
                                            "reads the case records, never stated")}
    level, unit = find_unit(ledger, ref)
    if unit is None:
        group = classes_by_handle(ledger, ref, hosts)
        if not group:
            cands = handle_candidates(ledger, ref)
            return {"success": False, "error": f"{ref!r} is no evidence item or class of this case"
                    + (f"; labels that match: {', '.join(repr(c) for c in cands)}" if cands else "")}
        return _set_group(case_dir, ledger, group, state, kind, reason, proof, by_code)
    if state == "left":
        verdict = check_leave(case_dir, ledger, ref, kind, reason, proof, by_code=by_code)
        if not verdict["ok"]:
            # Name the unit's readers, so the next step is a read of it.
            try:
                readers = readers_for(unit_format(case_dir, level, unit, _item_of(ledger, level, unit)))
            except Exception:  # noqa: BLE001
                readers = []
            return {"success": False, "gate": "evidence_leave", "error": verdict["error"]
                    + (f"; read it with {', '.join(readers[:4])}" if readers else "")}
        if level == "item":
            # An item is left as a whole only when each of its unread
            # classes can be left by the same reason; the classes that can
            # are left, the item stays when any cannot.
            failing = []
            for c in _classes_of(ledger, "item", unit):
                if c.get("state") not in ("pending", "relevant", "parsed"):
                    continue
                cv = check_leave(case_dir, ledger, c["id"], kind, reason, proof)
                if cv["ok"]:
                    c.update(state="left", reason_kind=kind, reason=f"with its item: {str(reason)[:400]}",
                             scope_fingerprint=scope_fingerprint(case_dir))
                else:
                    failing.append(f"{c['label']} ({cv['error'].split(': ', 1)[-1][:120]})")
            if failing:
                save_ledger(case_dir, ledger)
                return {"success": False, "gate": "evidence_leave",
                        "error": (f"{ref} cannot be left as a whole as {kind}: its classes "
                                  + "; ".join(failing[:4]) + " do not meet it; the others were left")}
        _leave(case_dir, unit, kind, reason, proof, verdict)
        save_ledger(case_dir, ledger)
        return {"success": True, "unit": unit["id"], "state": "left", "note": verdict.get("note", "")}
    unit.update(state=state, reason=str(reason)[:500])
    save_ledger(case_dir, ledger)
    return {"success": True, "unit": unit["id"], "state": state}


def _leave(case_dir, unit: dict[str, Any], kind: str, reason: str, proof: list | None, verdict: dict) -> None:
    """Write a leave that held onto the unit (in place): the hit an
    unreadable unit's listing holds joins its reason for the report."""
    text = str(reason)[:500]
    if verdict.get("note") and kind == "unreadable" and "a person must look" in verdict["note"]:
        text = (text + "; " + verdict["note"])[:500]
    # Call ids are stored as the numbers they parse to (a model's "call 5"
    # is 5); a duplicate's proof is the other item's path and stays.
    cited = list(proof or []) if kind == "duplicate_of" else proof_call_ids(proof)[0]
    unit.update(state="left", reason_kind=kind, reason=text,
                proof_call_ids=cited[:12], scope_fingerprint=scope_fingerprint(case_dir),
                scope_parts=scope_parts(case_dir), acknowledged_entities=attacker_entities(case_dir)[:200])


def _set_group(case_dir, ledger: dict[str, Any], group: list[dict[str, Any]], state: str, kind: str,
               reason: str, proof: list | None, by_code: bool) -> dict[str, Any]:
    """One label on several hosts: each open class of the group checked
    and left on its own; the answer names the hosts left and, per host
    refused, the checker's words."""
    from core.coverage_ledger import save_ledger
    from core.evidence_depth import unit_host
    items = ledger.get("items") or {}
    left: list[str] = []
    refused: dict[str, str] = {}
    skipped: list[str] = []
    for c in sorted(group, key=lambda c: str(c.get("host") or "")):
        # Each host as the block names it (unit_host: the host, else the
        # item's file name), so the answer and the block agree.
        host = unit_host(c, items) or str(c.get("item") or "?")
        if c.get("state") not in ("pending", "relevant", "parsed"):
            skipped.append(f"{host} ({c.get('state')})")
            continue
        if state == "relevant":
            c.update(state="relevant", reason=str(reason)[:500])
            left.append(host)
            continue
        verdict = check_leave(case_dir, ledger, c["id"], kind, reason, proof, by_code=by_code)
        if verdict["ok"]:
            _leave(case_dir, c, kind, reason, proof, verdict)
            left.append(host)
        else:
            refused[host] = verdict["error"].split(": ", 1)[-1][:300]
    if left:
        save_ledger(case_dir, ledger)
    label = str(group[0].get("label") or "")
    out: dict[str, Any] = {"success": bool(left) and not refused, "label": label, "state": state,
                           "hosts": left, "refused": refused}
    if skipped:
        out["already_decided"] = skipped
    if refused:
        out["error"] = (f"{label!r}: " + ("left on " + ", ".join(left) + "; " if left else "")
                        + "refused on " + "; ".join(f"{h}: {w}" for h, w in refused.items()))
    elif not left:
        out["error"] = f"{label!r}: no open class to leave" + (f" ({', '.join(skipped)})" if skipped else "")
    return out


def _rare_hit(case_dir, hit: str, memo: dict | None = None) -> bool:
    """A listing hit counts for a reopen only outside the paths most hosts
    share (the digest's rarity rule); an export hit always counts.
    ``memo``: per reopen pass, each folder judged once."""
    if "::" not in hit:
        return True
    path = hit.split("::", 1)[1]
    folder = path.rpartition("/")[0]
    if memo is not None and folder in memo:
        return memo[folder]
    rare = _folder_rare(case_dir, folder)
    if memo is not None:
        memo[folder] = rare
    return rare


def _folder_rare(case_dir, folder: str) -> bool:
    con = _index(case_dir)
    if con is None or not folder:
        return True
    from core.contents_index import _like_escape, is_specific
    with closing(con):
        total = con.execute("SELECT COUNT(DISTINCT host) FROM entries WHERE origin = 'image' AND host != ''").fetchone()[0]
        holders = con.execute("SELECT COUNT(DISTINCT host) FROM entries WHERE origin = 'image' AND path LIKE ? "
                              "ESCAPE '\\'", (_like_escape(folder) + "/%",)).fetchone()[0]
    return is_specific(holders, total or 1)


def scope_parts(case_dir) -> dict[str, str]:
    """The parts of the scope a leave is judged against, each hashed: the
    window start (outside_window), the hosts in scope (other_scope) and the
    attacker entities (the sweep)."""
    import hashlib

    def h(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    return {"window": h(window_start(case_dir)), "hosts": h(",".join(sorted(_named_hosts(case_dir)))),
            "entities": h(",".join(attacker_entities(case_dir)))}


# The part of the scope each kind's check reads; the other kinds do not
# depend on the scope.
_KIND_PART = {"outside_window": "window", "other_scope": "hosts"}


@_locked
def reopen_left(log, case_dir: str | os.PathLike) -> list[str]:
    """Once per turn: every left unit whose scope changed since its leave is
    checked again, only in the part its kind reads. A new attacker entity
    the sweep finds outside the paths most hosts share, or a leave that no
    longer holds, returns the unit to pending with the reason, as a due
    triage item. An entity acknowledged at a unit's last disposition never
    reopens it again. The inputs every unit shares (the window, the hosts in
    scope, the accounts their exports show, each folder's rarity) are
    computed once per pass. Returns the reopened unit ids."""
    from core.coverage_ledger import load_ledger, save_ledger
    ledger = load_ledger(case_dir)
    current = scope_fingerprint(case_dir)
    parts = scope_parts(case_dir)
    entities = attacker_entities(case_dir)
    reopened: list[str] = []
    touched = False
    ctx: dict[str, Any] | None = None
    memo: dict[str, bool] = {}
    left = [(level, u) for level, units in (("item", ledger.get("items") or {}),
                                             ("class", ledger.get("classes") or {}))
            for u in units.values()
            if isinstance(u, dict) and u.get("state") == "left" and u.get("scope_fingerprint") != current
            and not (level == "class" and str(u.get("reason") or "").startswith("with its item:"))
            and u.get("reason_kind")]
    for level, unit in left:
        old = unit.get("scope_parts") or {}
        item = _item_of(ledger, level, unit)
        seen = set(unit.get("acknowledged_entities") or [])
        new = [e for e in entities if e not in seen] if old.get("entities") != parts["entities"] else []
        hits = [h for h in sweep(case_dir, level, unit, item, new) if _rare_hit(case_dir, h, memo)] if new else []
        why = f"reopened: {hits[0]}" if hits else ""
        part = _KIND_PART.get(str(unit.get("reason_kind") or ""))
        if not why and part and old.get(part) != parts[part]:
            if ctx is None:
                ctx = _reopen_context(case_dir, ledger, [u for _l, u in left])
            verdict = check_leave(case_dir, ledger, unit["id"] if level == "class" else item["path"],
                                  str(unit.get("reason_kind") or ""), str(unit.get("reason") or "kept"),
                                  list(unit.get("proof_call_ids") or []), ignore_entities=frozenset(entities),
                                  ctx=ctx)
            if not verdict["ok"]:
                why = f"reopened: {verdict['error']}"
        unit["acknowledged_entities"] = sorted(seen | set(new))[:200]
        unit["scope_fingerprint"] = current
        unit["scope_parts"] = parts
        touched = True
        if not why:
            continue
        from core.evidence_disposition import reopen
        reopen(unit, why)
        unit["reason_kind"] = ""
        reopened.append(unit["id"])
        try:
            from core.evidence_triage import reopen_item
            reopen_item(log, case_dir, item, unit if level == "class" else None,
                        f"triage: {unit.get('label') or item['path']} {why[:200]}")
        except Exception:  # noqa: BLE001
            pass
    # Code leaves of the pass: a class whose data ends before the stated
    # window start is left outside_window by code, through the same check
    # a model leave takes (the window is this pass's, computed once).
    meta = ledger.setdefault("meta", {})
    if code_leaves_on() and meta.get("code_leave_window") != parts["window"]:
        # Once per window: the pass runs the code leaves again only when
        # the stated start moved (the part this kind reads).
        meta["code_leave_window"] = parts["window"]
        touched = True
        if ctx is None:
            ctx = {"window": window_start(case_dir)}
        if ctx.get("window"):
            for c in list((ledger.get("classes") or {}).values()):
                if not isinstance(c, dict) or c.get("state") not in ("pending", "relevant"):
                    continue
                item = _item_of(ledger, "class", c)
                if item.get("kind") == "memory":
                    continue
                verdict = check_leave(case_dir, ledger, c["id"], "outside_window",
                                      f"by code: its data ends before the earliest stated start {ctx['window']}",
                                      [], ctx=ctx, by_code=True)
                if verdict["ok"]:
                    _leave(case_dir, c, "outside_window", f"by code: its data ends before the earliest stated "
                           f"start {ctx['window']}", [], verdict)
                    touched = True
    if touched:
        save_ledger(case_dir, ledger)
    return reopened


def code_leaves_on() -> bool:
    """ATLAS_CODE_LEAVES: the kinds code decides itself (empty at build,
    unreadable on a failed read, outside_window in the reopen pass)."""
    from core.envfile import env_flag
    return env_flag("ATLAS_CODE_LEAVES", True)


def _reopen_context(case_dir, ledger: dict[str, Any], units: list[dict[str, Any]]) -> dict[str, Any]:
    """The inputs every re-judged leave shares: the window start, the hosts
    in scope, and in one native count over those hosts' exports which of the
    left items' accounts appear there."""
    named = _named_hosts(case_dir)
    ctx: dict[str, Any] = {"window": window_start(case_dir), "named": named, "accounts_in_exports": set()}
    profiles = _profiles(case_dir)
    hosts = {str(_item_of(ledger, u.get("level") or "item", u).get("host") or "").casefold() for u in units}
    accounts = sorted({p for h in hosts for p in profiles.get(h, set())})
    exports = [e for h in named for e in _host_exports(case_dir, h)]
    if accounts and exports:
        try:
            from tools.tabular import count_values
            counts = count_values(str(case_dir), accounts, exports, {a: "account" for a in accounts}).get("counts") or {}
            ctx["accounts_in_exports"] = {a for a, per in counts.items()
                                          if any((c or {}).get("full") for c in (per or {}).values())}
        except Exception:  # noqa: BLE001
            pass
    return ctx


def scope_fingerprint(case_dir) -> str:
    """What a leave was judged against: the window start, the hosts in
    scope and the attacker entities."""
    import hashlib
    blob = "|".join([window_start(case_dir), ",".join(sorted(_named_hosts(case_dir))),
                     ",".join(attacker_entities(case_dir))])
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
