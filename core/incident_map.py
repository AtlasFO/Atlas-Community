"""The incident map (ATLAS_INCIDENT_MAP): a typed store of the incident
beside the claim graph, at ``.atlas/incident_map.db``.

Beliefs stay in the claim graph. The map holds what they are about as data:
entities (host, account, file, endpoint, evidence item, observation), timed
events that connect them, and labels (attacker, benign, unknown) that the
model sets, each citing the belief or the calls that show it. Code never
labels; it keys values, keeps label currency with the beliefs, and writes
every change to an append-only feed (``changes``) that consumers follow
with a cursor.

Label rules:
- belief-backed: the label's claim_id names a current belief; a proposal
  otherwise (written from calls alone). Proposals raise changes but never
  count as established;
- currency per claim: a superseded or withdrawn belief turns every label
  citing it non-current, whoever wrote the label;
- latest wins per basis: per target, the newest label of one claim (or of
  the call-only basis) counts; current labels of two bases that differ
  raise ``label_conflict``.

Sync: the graph file's content hash is its revision (``save_graph``
replaces the file atomically; no hook inside the graph's lock is needed).
Every entry point compares that revision with the last one synced and
ingests the beliefs whose content changed. The graph is loaded before the map lock is taken and the two
locks are never held together. The coverage ledger's evidence items and
classes are mirrored the same way; their state is read, never kept as
the map's own.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

DB_NAME = "incident_map.db"
ENTITY_KINDS = ("host", "account", "file", "endpoint", "evidence_item", "observation")
EVENT_KINDS = ("logon", "process", "file_write", "file_delete", "connection", "persistence", "access", "other")
ROLES = ("actor", "src", "dst", "object", "parent", "via")
LABELS = ("attacker", "benign", "unknown")
# Indicator side to label: the typed side is the model's own word.
_SIDE_LABEL = {"attacker": "attacker", "victim": "benign", "subject": "benign",
               "third_party": "benign", "undetermined": "unknown"}
_ENDPOINT_TYPES = ("ip", "domain", "url", "email")
_HASH_ATTR = {32: "md5", 40: "sha1", 64: "sha256"}
_STRONG = ("LIKELY", "CONFIRMED")
_COARSE = "e.kind = 'other' AND e.verb = 'belief'"
_CHECKS = ("seen_before_start", "account_before_start")
# What a view may range over and the column paths it may name: the map's
# own computations and attributes, no question shape.
_VIEW_OVER = ("host", "account", "file", "endpoint")
_HOST_COLUMNS = ("label", "first_attacker_event.time", "first_attacker_event.verb", "first_attacker_event.claim",
                 "start.time", "start.via", "start.claim", "inbound.src", "inbound.verb", "inbound.actor",
                 "inbound.time")
_ENTITY_COLUMNS = ("label", "hosts", "first_attacker_event.time", "first_attacker_event.verb",
                   "first_attacker_event.host", "start.time", "start.claim")
_EVENT_COLUMNS = ("time", "host", "verb", "actor", "object", "src", "dst", "label")

_LOCK = threading.RLock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
  eid INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, key TEXT, host TEXT, display TEXT, attrs TEXT,
  created_seq INTEGER, name TEXT, UNIQUE(kind, key, host));
CREATE INDEX IF NOT EXISTS entities_name ON entities(kind, name);
CREATE TABLE IF NOT EXISTS entity_hashes (eid INTEGER, value TEXT, UNIQUE(eid, value));
CREATE INDEX IF NOT EXISTS entity_hashes_value ON entity_hashes(value);
CREATE TABLE IF NOT EXISTS events (
  vid INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, verb TEXT, t TEXT, t_end TEXT, host TEXT,
  source TEXT, claim_id TEXT, created_seq INTEGER);
CREATE INDEX IF NOT EXISTS events_claim ON events(claim_id);
CREATE TABLE IF NOT EXISTS roles (vid INTEGER, eid INTEGER, role TEXT, UNIQUE(vid, eid, role));
CREATE INDEX IF NOT EXISTS roles_eid ON roles(eid);
CREATE TABLE IF NOT EXISTS labels (
  lid INTEGER PRIMARY KEY, target TEXT, label TEXT, claim_id TEXT, call_ids TEXT, reason TEXT,
  by TEXT, seq INTEGER, current INTEGER, proposal INTEGER);
CREATE INDEX IF NOT EXISTS labels_target ON labels(target);
CREATE INDEX IF NOT EXISTS labels_claim ON labels(claim_id);
CREATE TABLE IF NOT EXISTS sightings (
  entity_id INTEGER, host TEXT, source TEXT, call_id INTEGER, t TEXT, seq INTEGER,
  UNIQUE(entity_id, host, source, call_id, t));
CREATE TABLE IF NOT EXISTS views (
  view_id INTEGER PRIMARY KEY, task_id TEXT, part_id TEXT, spec TEXT,
  declared_by TEXT, seq INTEGER, current INTEGER);
CREATE TABLE IF NOT EXISTS ingested (
  claim_id TEXT PRIMARY KEY, version TEXT, current INTEGER, tier TEXT, host TEXT,
  noted INTEGER, statement TEXT, noted_mark INTEGER);
CREATE TABLE IF NOT EXISTS anchors (claim_id TEXT, kind TEXT, value TEXT, t TEXT);
CREATE INDEX IF NOT EXISTS anchors_claim ON anchors(claim_id);
CREATE TABLE IF NOT EXISTS changes (
  seq INTEGER PRIMARY KEY, kind TEXT, fields TEXT, ts TEXT, once_key TEXT UNIQUE);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

# A label counts when it is the newest of its basis for the target and the
# belief it cites (if any) has not been retired.
# The basis of a label the case brief states (the user's own statement).
BRIEF = "brief"
_CURRENT = ("l.current = 1 AND COALESCE((SELECT i.current FROM ingested i "
            "WHERE i.claim_id = l.claim_id), 1) = 1")


def _own(fallback: bool) -> str:
    """The once_key's bound source: a pair is checked once against the
    estate start (the base key) and once more against the host's or
    account's own start, when one is stated (":own"). At most two raises
    per pair: a later move of the own start does not raise again, since the
    key names the source, never the time."""
    return "" if fallback else ":own"


def map_on() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_INCIDENT_MAP", True)


def db_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir) / ".atlas" / DB_NAME


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# A date and time written in a line of text (ISO, with or without the T, a
# fraction and a zone): the candidates row_ref_for_time reads in a text row.
_TIME_IN_TEXT_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")


def _iso(text: Any) -> str:
    from core.incident_window import _iso as iso
    return iso(str(text or "")) if text else ""


def _content_sig(path: Path) -> str:
    """The revision of a file: its content hash (two writes inside one
    timestamp tick can keep a file's size and time)."""
    try:
        return hashlib.sha1(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def account_key(value: str) -> str:
    """The lower-case name of an account in any notation: ``DOMAIN\\name``,
    ``name@domain`` and the bare name fold to it. A host-local account is
    also bound to its host (IncidentMap.account_identity)."""
    v = str(value or "").strip().lower()
    if "\\" in v:
        v = v.rsplit("\\", 1)[1]
    elif "@" in v:
        v = v.split("@", 1)[0]
    return v


def _fold(text: str) -> str:
    return " ".join(str(text or "").split()).lower()


def open(case_dir: str | os.PathLike | None) -> Optional["IncidentMap"]:  # noqa: A001 - the API's name
    """The case's map, synced with the claim graph; None when the map is
    off or there is no case."""
    if not case_dir or not map_on():
        return None
    m = IncidentMap(case_dir)
    m.sync()
    return m


def record_notes(case_dir: str | os.PathLike | None) -> list[str]:
    """Sync the map after a finding is recorded and return the notes its
    checks raised (an attacker-labelled value seen on a host, or an account
    acting, before the anchored start; two beliefs labelling one value
    differently). Disclosures, never refusals."""
    if not case_dir or not map_on():
        return []
    m = IncidentMap(case_dir)
    with m._read() as con:
        head = m._seq(con)
    m.sync()
    return [n for n in (m.note_text(c) for c in m.changes_since(head)[0]) if n]


def views_on() -> bool:
    """ATLAS_MAP_VIEWS: question parts as views with open rows (the PLAN
    reply's view, the composer's VIEW block)."""
    from core.envfile import env_flag
    return map_on() and env_flag("ATLAS_MAP_VIEWS", True)


def signals_on() -> bool:
    """ATLAS_MAP_SIGNALS_TO_WORK_ORDER: the map's signals become work items
    (off: they are logged and shown only)."""
    from core.envfile import env_flag
    return map_on() and env_flag("ATLAS_MAP_SIGNALS_TO_WORK_ORDER", True)


def feed_work_items(log, case_dir: str | os.PathLike | None, cursor: int = 0) -> int:
    """Sync the map once (the loop calls this each turn) and turn the new
    changes after ``cursor`` into work items whose origin is the change
    kind. Specific joins fold per host: one item per host an attacker
    value reaches, its reason listing the values most specific first. The
    item is due (a read of the host's evidence) when the host has no
    attacker event, else a proposal for the director; a host whose
    evidence a call already read gets it closed at once. A host's due set
    is bounded by the hosts, never by a count. host_without_inbound is
    shown, never an item, and so is a view's open row: it stays in the
    view (an older trace's per-row items are moot, no read closes them).
    Returns the new cursor; re-reading the feed is safe (an item is found
    again by its fingerprint, a closed one never reopens)."""
    from core.work_order import resolve_items
    resolve_items(log, "view_row_opened", {"kind": "view_row"}, "its view no longer makes items", status="moot")
    m = open(case_dir)
    if m is None:
        return cursor
    changes, new = m.changes_since(cursor)
    if signals_on():
        hosts = {c["fields"]["host"] for c in changes if c["kind"] == "join_hit"}
        if hosts:
            m.host_join_items(log, hosts)
    return new


class IncidentMap:
    def __init__(self, case_dir: str | os.PathLike, readonly: bool = False):
        """``readonly``: a reader that never creates, syncs or writes the
        store (the dashboard's read model)."""
        self.case_dir = str(Path(case_dir).resolve())
        self.path = db_path(self.case_dir)
        self.readonly = readonly
        self._hosts_cache: Optional[list[str]] = None

    # ── connection ───────────────────────────────────────────────────────

    def _con(self) -> sqlite3.Connection:
        if self.readonly:
            con = sqlite3.connect(f"{self.path.as_uri()}?mode=ro", uri=True, timeout=30)
            con.row_factory = sqlite3.Row
            return con
        self.path.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript(_SCHEMA)
        return con

    @contextmanager
    def _read(self):
        con = self._con()
        try:
            yield con
        finally:
            con.close()

    @contextmanager
    def _write(self):
        with _LOCK:
            con = self._con()
            # What this transaction touched: the derive rechecks only these
            # (and everything when a window start moves).
            self._dirty: set[int] = set()
            self._dirty_v: set[int] = set()
            try:
                con.execute("BEGIN IMMEDIATE")
                yield con
                self._derive(con)
                con.execute("COMMIT")
            except BaseException:
                con.execute("ROLLBACK")
                raise
            finally:
                con.close()

    @staticmethod
    def _meta(con: sqlite3.Connection, key: str, default: Any = None) -> Any:
        row = con.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    @staticmethod
    def _set_meta(con: sqlite3.Connection, key: str, value: Any) -> None:
        con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, json.dumps(value)))

    @staticmethod
    def _change(con: sqlite3.Connection, kind: str, fields: dict[str, Any], once_key: str | None = None) -> None:
        con.execute("INSERT OR IGNORE INTO changes(kind, fields, ts, once_key) VALUES (?, ?, ?, ?)",
                    (kind, json.dumps(fields, sort_keys=True, default=str), _now(), once_key))

    @staticmethod
    def _seq(con: sqlite3.Connection) -> int:
        return int(con.execute("SELECT COALESCE(MAX(seq), 0) FROM changes").fetchone()[0])

    # ── keys ─────────────────────────────────────────────────────────────

    def _hosts(self) -> list[str]:
        if self._hosts_cache is None:
            try:
                from core.forensic_citation import known_case_hosts
                self._hosts_cache = known_case_hosts(self.case_dir)
            except Exception:  # noqa: BLE001
                self._hosts_cache = []
        return self._hosts_cache

    def case_host(self, host: Any) -> str:
        """The Evidence Links label of a host as written (aliases and FQDNs
        resolve); "" when it names no case host. With no Evidence Links the
        name stands as written."""
        h = str(host or "").strip()
        if not h:
            return ""
        hosts = self._hosts()
        if not hosts:
            return h
        for x in hosts:
            if x.casefold() == h.casefold():
                return x
        from core.claim_graph import same_host
        return next((x for x in hosts if same_host(x, h)), "")

    def account_identity(self, value: str, host: str = "") -> tuple[str, str, bool]:
        """(key, bound host, qualified) of an account as written. A
        qualifier that names a case host, or the local-machine notation
        (".\\name" on ``host``), binds the account to that host: one
        machine's local account is not another's. A domain, a UPN or a
        bare name folds to the lower-case name, host-less."""
        v = str(value or "").strip()
        if "\\" in v:
            qual = v.rsplit("\\", 1)[0].strip()
            bound = (self.case_host(host) if qual in (".", "") else
                     (self.case_host(qual) if self._hosts() else ""))
            return account_key(v), bound, True
        return account_key(v), "", "@" in v

    @staticmethod
    def account_id(key: str, host: str) -> str:
        """One string per account identity: the name, or HOST\\name for a
        host-local account."""
        return f"{host}\\{key}" if host else key

    def _key(self, kind: str, value: str, host: str = "") -> tuple[str, str, dict[str, Any]]:
        """(key, host column, attributes) of a value of an entity kind."""
        v = " ".join(str(value or "").split())
        if kind == "host":
            label = self.case_host(v) or v
            return label.lower(), "", {}
        if kind == "account":
            key, bound, qualified = self.account_identity(v, host)
            return key, bound, {"forms": [v], "qualified": qualified}
        if kind == "file":
            low = v.lower()
            if len(low) in _HASH_ATTR and all(c in "0123456789abcdef" for c in low):
                return low, "", {_HASH_ATTR[len(low)]: low}
            return low.replace("\\", "/"), self.case_host(host) or str(host or ""), {}
        if kind == "endpoint":
            return v.lower(), "", {}
        if kind in ("evidence_item", "observation"):
            return v, self.case_host(host) or str(host or ""), {}
        raise ValueError(f"unknown entity kind {kind!r} (one of {', '.join(ENTITY_KINDS)})")

    # ── sync with the claim graph and the coverage ledger ────────────────

    def sync(self) -> None:
        if self.readonly:
            return
        from core.claim_graph import claim_graph_path
        from core.coverage_ledger import ledger_path
        from core.investigation_tasks import tasks_path
        gsig, lsig = _content_sig(claim_graph_path(self.case_dir)), _content_sig(ledger_path(self.case_dir))
        tsig = _content_sig(tasks_path(self.case_dir)) if views_on() else ""
        with self._read() as con:
            if (self._meta(con, "graph_sig") == gsig and self._meta(con, "ledger_sig") == lsig
                    and self._meta(con, "tasks_sig", "") == tsig):
                return
            g_due, l_due = self._meta(con, "graph_sig") != gsig, self._meta(con, "ledger_sig") != lsig
            t_due = self._meta(con, "tasks_sig", "") != tsig
        graph = ledger = None
        if g_due:
            from core.claim_graph import load_graph
            graph = load_graph(self.case_dir)
        if l_due:
            from core.coverage_ledger import load_ledger
            ledger = load_ledger(self.case_dir)
        tasks = None
        if t_due and tsig:
            from core.investigation_tasks import load_tasks
            tasks = load_tasks(self.case_dir)
        with self._write() as con:
            if t_due:
                if tasks is not None:
                    self._sync_parts(con, tasks)
                self._set_meta(con, "tasks_sig", tsig)
            if graph is not None:
                for cid, node in (graph.get("nodes") or {}).items():
                    if isinstance(node, dict) and node.get("kind") in ("claim", "conclusion"):
                        self._ingest(con, str(cid), node)
                self._set_meta(con, "graph_sig", gsig)
            if ledger is not None:
                self._mirror_ledger(con, ledger)
                self._set_meta(con, "ledger_sig", lsig)

    def ingest_belief(self, claim_id: str) -> dict[str, Any]:
        """One belief of the claim graph into entities, events and labels
        (the sync does this for every changed belief)."""
        from core.claim_graph import load_graph
        self.sync()
        node = (load_graph(self.case_dir).get("nodes") or {}).get(str(claim_id))
        if not isinstance(node, dict):
            return {"ok": False, "notes": [f"no belief {claim_id} in the claim graph"]}
        with self._write() as con:
            self._ingest(con, str(claim_id), node)
        return {"ok": True, "notes": []}

    @staticmethod
    def _version(node: dict[str, Any]) -> str:
        keep = {k: node.get(k) for k in ("status", "confidence", "host", "statement", "indicators",
                                         "input_call_ids", "window_noted", "window_noted_mark")}
        return hashlib.sha1(json.dumps(keep, sort_keys=True, default=str).encode()).hexdigest()

    def _ingest(self, con: sqlite3.Connection, cid: str, node: dict[str, Any]) -> None:
        from core.claim_graph import is_current_belief
        version = self._version(node)
        row = con.execute("SELECT version FROM ingested WHERE claim_id = ?", (cid,)).fetchone()
        if row and row[0] == version:
            return
        current = is_current_belief(node)
        touched = [r[0] for r in con.execute("SELECT DISTINCT target FROM labels WHERE claim_id = ?", (cid,))]
        for t in touched:
            (self._dirty if t.startswith("e:") else self._dirty_v).add(int(t[2:]))
        before = {t: self._state(con, t) for t in touched}
        host = self.case_host(node.get("host"))
        con.execute("INSERT OR REPLACE INTO ingested VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (cid, version, int(current), str(node.get("confidence") or "").upper(), host,
                     int(bool(node.get("window_noted"))), str(node.get("statement") or ""),
                     int(node.get("window_noted_mark") or 0)))
        # The previous version's derivation goes; the new one replaces it.
        con.execute("UPDATE labels SET current = 0 WHERE claim_id = ? AND by = 'ingest'", (cid,))
        con.execute("DELETE FROM anchors WHERE claim_id = ?", (cid,))
        # Its rows' sightings go too (re-derived below while current): a
        # retired belief's hosts never count as an entity's.
        con.execute("DELETE FROM sightings WHERE source = ?", (f"row:{cid}",))
        if current:
            self._derive_belief(con, cid, node, host, before)
        else:
            for (vid,) in con.execute("SELECT vid FROM events WHERE claim_id = ? AND kind = 'other' "
                                      "AND verb = 'belief'", (cid,)).fetchall():
                self._dirty_v.add(vid)
                con.execute("DELETE FROM roles WHERE vid = ?", (vid,))
                con.execute("DELETE FROM events WHERE vid = ?", (vid,))
        self._emit_labels(con, before)

    def _derive_belief(self, con: sqlite3.Connection, cid: str, node: dict[str, Any], host: str,
                       before: dict[str, tuple]) -> None:
        from core.indicators import rows_of, shared_mark
        from core.incident_window import leading_time
        calls = [int(c) for c in node.get("input_call_ids") or [] if str(c).lstrip("-").isdigit()]
        objects: list[int] = []
        actors: list[int] = []
        attacker = False
        for r in rows_of(node):
            kind, value, side = str(r.get("type")), str(r.get("value") or ""), str(r.get("side") or "")
            if not value:
                continue
            if kind in ("host", "account"):
                ekind, attrs = kind, {}
            elif kind in ("path", "file", "hash"):
                ekind, attrs = "file", {}
            elif kind in _ENDPOINT_TYPES:
                ekind, attrs = "endpoint", {"type": kind}
                mark = shared_mark(kind, value)
                if mark:
                    attrs["shared"] = mark
            else:
                # service, task, registry and the other typed values: kept as
                # file-less entities keyed as written, so nothing is lost.
                ekind, attrs = "file", {"kind_as_typed": kind}
            stated = _iso(r.get("attacker_from"))
            if stated and kind in ("host", "account"):
                # When the attacker first acted on this host or with this
                # account, stated by the belief (a window anchor at LIKELY+).
                anchor = ((self.case_host(value) or value) if kind == "host"
                          else self.account_id(*self.account_identity(value, host)[:2]))
                con.execute("INSERT INTO anchors VALUES (?, ?, ?, ?)", (cid, kind, anchor, stated))
            ehost = host if (ekind == "file" and kind in ("path", "file")) or ekind == "account" else ""
            value_key = value if "kind_as_typed" not in attrs else f"{kind}:{value}"
            eid = self._upsert(con, ekind, value_key, ehost, attrs, display=value)
            (actors if ekind == "account" else objects).append(eid)
            label = _SIDE_LABEL.get(side)
            if label:
                target = f"e:{eid}"
                before.setdefault(target, self._state(con, target))
                self._put_label(con, target, label, cid, calls, f"side:{side}", "ingest")
                attacker = attacker or label == "attacker"
            for s in r.get("sightings") or []:
                if isinstance(s, dict):
                    sh = self.case_host(s.get("host"))
                    if sh:
                        self._sight(con, eid, sh, f"row:{cid}", int(s.get("call") or 0), _iso(s.get("first")))
        t = leading_time(str(node.get("statement") or ""))
        old = con.execute("SELECT vid FROM events WHERE claim_id = ? AND kind = 'other' AND verb = 'belief'",
                          (cid,)).fetchone()
        if not (host and t):
            if old:
                con.execute("DELETE FROM roles WHERE vid = ?", (old[0],))
                con.execute("DELETE FROM events WHERE vid = ?", (old[0],))
            return
        source = json.dumps({"claim_id": cid, "call_ids": calls})
        if old:
            vid = int(old[0])
            con.execute("UPDATE events SET t = ?, host = ?, source = ? WHERE vid = ?", (t, host, source, vid))
            con.execute("DELETE FROM roles WHERE vid = ?", (vid,))
        else:
            vid = int(con.execute(
                "INSERT INTO events(kind, verb, t, t_end, host, source, claim_id, created_seq) "
                "VALUES ('other', 'belief', ?, '', ?, ?, ?, ?)", (t, host, source, cid, self._seq(con))).lastrowid)
        self._dirty_v.add(vid)
        for eid in objects:
            con.execute("INSERT OR IGNORE INTO roles VALUES (?, ?, 'object')", (vid, eid))
        for eid in actors:
            con.execute("INSERT OR IGNORE INTO roles VALUES (?, ?, 'actor')", (vid, eid))
        if attacker:
            self._put_label(con, f"v:{vid}", "attacker", cid, calls, "a typed row is attacker-side", "ingest")

    def _mirror_ledger(self, con: sqlite3.Connection, ledger: dict[str, Any]) -> None:
        """Each item and class unit of the coverage ledger as a host-linked
        node of kind evidence_item; a unit entering pending (new, or
        reopened) raises ``evidence_item_pending``."""
        seen = self._meta(con, "ledger_states", {})
        now: dict[str, str] = {}
        for level, units in (("item", ledger.get("items")), ("class", ledger.get("classes"))):
            for uid, u in (units or {}).items():
                if not isinstance(u, dict) or "state" not in u:
                    continue
                uid = str(u.get("id") or uid)
                host = self.case_host(u.get("host"))
                display = str(u.get("label") or Path(str(u.get("path") or uid)).name)
                self._upsert(con, "evidence_item", uid, host, {"level": level}, display=display)
                state = str(u.get("state") or "pending")
                mark = [state, int(u.get("reopened") or 0)]
                now[uid] = mark
                was = seen.get(uid)
                was = was if isinstance(was, list) else [was, 0]
                if state == "pending" and (was[0] != "pending" or mark[1] > was[1]):
                    self._change(con, "evidence_item_pending", {"item_id": uid, "level": level, "host": host})
        self._set_meta(con, "ledger_states", now)

    # ── low-level writes ─────────────────────────────────────────────────

    def _upsert(self, con: sqlite3.Connection, kind: str, value: str, host: str = "",
                attrs: dict[str, Any] | None = None, display: str = "") -> int:
        key, hcol, extra = self._key(kind, value, host)
        merged = {**extra, **(attrs or {})}
        row = con.execute("SELECT eid, attrs FROM entities WHERE kind = ? AND key = ? AND host = ?",
                          (kind, key, hcol)).fetchone()
        if row:
            old = json.loads(row["attrs"] or "{}")
            forms = list(dict.fromkeys((old.get("forms") or []) + (merged.pop("forms", None) or [])))
            if "qualified" in merged:
                merged["qualified"] = bool(merged["qualified"] or old.get("qualified"))
            new = {**old, **merged, **({"forms": forms} if forms else {})}
            eid = int(row["eid"])
            if new != old:
                con.execute("UPDATE entities SET attrs = ? WHERE eid = ?", (json.dumps(new, sort_keys=True), eid))
                self._index_hashes(con, eid, new)
                self._dirty.add(eid)
            return eid
        name = key.rsplit("/", 1)[-1] if kind == "file" else ""
        eid = int(con.execute(
            "INSERT INTO entities(kind, key, host, display, attrs, created_seq, name) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (kind, key, hcol, display or " ".join(str(value).split()), json.dumps(merged, sort_keys=True),
             self._seq(con), name)).lastrowid)
        self._index_hashes(con, eid, merged)
        self._dirty.add(eid)
        return eid

    @staticmethod
    def _index_hashes(con: sqlite3.Connection, eid: int, attrs: dict[str, Any]) -> None:
        for k in _HASH_ATTR.values():
            if attrs.get(k):
                con.execute("INSERT OR IGNORE INTO entity_hashes VALUES (?, ?)", (eid, str(attrs[k]).lower()))

    def _sight(self, con: sqlite3.Connection, eid: int, host: str, source: str, call_id: int, t: str) -> None:
        con.execute("INSERT OR IGNORE INTO sightings VALUES (?, ?, ?, ?, ?, ?)",
                    (eid, host, source, call_id, t or "", self._seq(con)))
        self._dirty.add(int(eid))

    def _put_label(self, con: sqlite3.Connection, target: str, label: str, claim_id: str,
                   call_ids: Iterable[Any], reason: str, by: str) -> int:
        row = con.execute("SELECT current FROM ingested WHERE claim_id = ?", (claim_id,)).fetchone() if claim_id else None
        # A label the brief states is the user's own statement: held like a
        # belief (so a finding against it raises a conflict), never a guess.
        proposal = 0 if (row and row[0]) or by == BRIEF else 1
        (self._dirty if target.startswith("e:") else self._dirty_v).add(int(target[2:]))
        con.execute("UPDATE labels SET current = 0 WHERE target = ? AND claim_id = ?", (target, claim_id))
        con.execute("INSERT INTO labels(target, label, claim_id, call_ids, reason, by, seq, current, proposal) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
                    (target, label, claim_id, json.dumps(list(call_ids)), reason, by, self._seq(con), proposal))
        return proposal

    @staticmethod
    def _current_labels(con: sqlite3.Connection, target: str) -> list[sqlite3.Row]:
        return con.execute(f"SELECT * FROM labels l WHERE l.target = ? AND {_CURRENT} ORDER BY l.seq, l.lid",
                           (target,)).fetchall()

    def _state(self, con: sqlite3.Connection, target: str) -> tuple[Optional[str], int]:
        """(label, proposal) a target counts as: attacker when any current
        belief-backed label says so (the conservative reading while two
        beliefs disagree, which raises a conflict), else the newest current
        belief-backed label, else the newest current proposal."""
        rows = self._current_labels(con, target)
        backed = [r for r in rows if not r["proposal"]]
        if any(r["label"] == "attacker" for r in backed):
            return "attacker", 0
        if backed:
            return backed[-1]["label"], 0
        return (rows[-1]["label"], 1) if rows else (None, 0)

    def _emit_labels(self, con: sqlite3.Connection, before: dict[str, tuple]) -> None:
        for target, was in sorted(before.items()):
            if not target.startswith("e:"):
                continue
            now = self._state(con, target)
            if now == was:
                continue
            e = con.execute("SELECT * FROM entities WHERE eid = ?", (int(target[2:]),)).fetchone()
            if e:
                self._change(con, "entity_labeled", {
                    "entity_id": e["eid"], "kind": e["kind"], "value": e["display"], "label": now[0],
                    "host": e["host"], "proposal": bool(now[1])})

    # ── derived state, recomputed after every write ──────────────────────

    def _attacker_events(self, con: sqlite3.Connection) -> list[sqlite3.Row]:
        return con.execute(
            "SELECT DISTINCT e.* FROM events e JOIN labels l ON l.target = 'v:' || e.vid "
            f"WHERE {_CURRENT} AND l.proposal = 0 AND l.label = 'attacker' AND e.t != '' AND e.host != '' "
            "ORDER BY e.t, e.vid").fetchall()

    def _derive(self, con: sqlite3.Connection) -> None:
        firsts: dict[str, list] = {}
        for e in self._attacker_events(con):
            firsts.setdefault(e["host"], [e["t"], e["vid"]])
        old = self._meta(con, "host_first", {})
        for host, (t, vid) in sorted(firsts.items()):
            if host not in old or t < old[host][0]:
                self._change(con, "host_attacker_event", {"host": host, "event_id": vid, "time": t})
        if firsts != old:
            self._set_meta(con, "host_first", firsts)
        # A conflict is attacker against benign; unknown takes no position.
        for target, joined in con.execute(
                f"SELECT l.target, GROUP_CONCAT(DISTINCT l.label) FROM labels l WHERE {_CURRENT} "
                "AND l.proposal = 0 AND l.label != 'unknown' GROUP BY l.target "
                "HAVING COUNT(DISTINCT l.label) > 1").fetchall():
            labels = sorted(joined.split(","))
            stated = con.execute(f"SELECT l.label FROM labels l WHERE l.target = ? AND {_CURRENT} AND l.by = ? "
                                 "AND l.label != 'unknown'", (target, BRIEF)).fetchone()
            self._change(con, "label_conflict", {"ref": target, "labels": labels,
                                                 **({"brief": target, "brief_label": stated[0]} if stated else {})},
                         once_key=f"conflict:{target}:{','.join(labels)}")
        # A file the brief states a side for names it on no host: the same
        # file on a host that a belief labels the other way is a conflict
        # with the user's own statement. A brief file named without a
        # directory is the file of that name in any directory.
        for target, label, kind, key in con.execute(
                f"SELECT l.target, l.label, n.kind, n.key FROM labels l JOIN entities n ON 'e:' || n.eid = l.target "
                f"WHERE {_CURRENT} AND l.by = ? AND l.label != 'unknown' AND n.host = ''", (BRIEF,)).fetchall():
            bare = int(kind == "file" and "/" not in key)
            for other, olabel in con.execute(
                    f"SELECT l.target, l.label FROM labels l JOIN entities n ON 'e:' || n.eid = l.target "
                    f"WHERE {_CURRENT} AND l.proposal = 0 AND l.label NOT IN ('unknown', ?) AND n.kind = ? "
                    "AND (n.key = ? OR (? AND substr(n.key, -length(?) - 1) = '/' || ?)) AND n.host != ''",
                    (label, kind, key, bare, key, key)).fetchall():
                labels = sorted({label, olabel})
                self._change(con, "label_conflict", {"ref": other, "labels": labels, "brief": target,
                                                     "brief_label": label},
                             once_key=f"conflict:{other}:{','.join(labels)}")
        w = self._window_core(con)
        starts = {h: v[0][0] for h, v in w["hosts"].items()}
        starts[""] = w["estate"][0] if w["estate"] else ""
        # Account starts move the account check of events no write touched.
        starts.update({f"acct|{a}": v[0][0] for a, v in w["accounts"].items()})
        old_starts = self._meta(con, "starts")
        attackers = set(self._attacker_eids(con))
        known = self._meta(con, "attackers")
        # A moved start or a first derive rechecks everything; otherwise only
        # what this write touched and the entities that became attacker.
        full = old_starts is None or starts != old_starts or known is None
        fresh = attackers - set(known or [])
        # Events first: an event noted here no longer anchors, so the
        # window is recomputed until the noted set stops growing (it only
        # grows, so this ends); the values' sightings are checked against
        # the settled window.
        only, only_v = (None, None) if full else (self._dirty | fresh, self._dirty_v)
        seen = self._noted_events(con)
        self._window_checks(con, w, only, only_v, entities=False)
        now_noted = self._noted_events(con)
        while now_noted != seen:
            seen = now_noted
            w = self._window_core(con)
            self._window_checks(con, w, entities=False)
            now_noted = self._noted_events(con)
        starts = {h: v[0][0] for h, v in w["hosts"].items()}
        starts[""] = w["estate"][0] if w["estate"] else ""
        starts.update({f"acct|{a}": v[0][0] for a, v in w["accounts"].items()})
        if starts != old_starts:
            only = only_v = None
        self._window_checks(con, w, only, only_v, events=False)
        for h in sorted(set(starts) | set(old_starts or {})):
            if h.startswith("acct|"):
                continue
            if starts.get(h, "") != (old_starts or {}).get(h, ""):
                self._change(con, "window_changed", {"host": h or None})
        if starts != old_starts:
            self._set_meta(con, "starts", starts)
        inbound = self._inbound_hosts(con)
        for host in sorted(firsts):
            if host not in inbound:
                self._change(con, "host_without_inbound", {"host": host}, once_key=f"hwi:{host}")
        self._joins(con, attackers if known is None else attackers & (self._dirty | fresh | self._twins(con)))
        if known is None or set(known) != attackers:
            self._set_meta(con, "attackers", sorted(attackers))
        self._derive_views(con)

    # ── the window and its checks (code, no model) ───────────────────────

    def _backed_events(self, con: sqlite3.Connection, fine_only: bool = False) -> list[sqlite3.Row]:
        """Attacker events with the belief that labels them (one row per
        backing belief), that belief's tier and its window mark."""
        return con.execute(
            "SELECT e.*, l.claim_id AS by_claim, i.tier, i.noted, i.statement, i.noted_mark FROM events e "
            "JOIN labels l ON l.target = 'v:' || e.vid JOIN ingested i ON i.claim_id = l.claim_id "
            "WHERE l.current = 1 AND i.current = 1 AND l.proposal = 0 AND l.label = 'attacker' AND e.t != '' "
            + (f"AND NOT ({_COARSE}) " if fine_only else "") + "ORDER BY e.t, e.vid").fetchall()

    @staticmethod
    def _role_entities(con: sqlite3.Connection, vid: int, role: str, kind: str) -> list[sqlite3.Row]:
        return con.execute("SELECT n.* FROM roles r JOIN entities n ON n.eid = r.eid "
                           "WHERE r.vid = ? AND r.role = ? AND n.kind = ?", (vid, role, kind)).fetchall()

    @staticmethod
    def _noted_events(con: sqlite3.Connection) -> dict[int, int]:
        """{event id: the trace position of its latest note}."""
        out: dict[int, int] = {}
        for (fields,) in con.execute(f"SELECT fields FROM changes WHERE kind IN {_CHECKS!r}"):
            f = json.loads(fields)
            if f.get("event_id"):
                vid = int(f["event_id"])
                out[vid] = max(out.get(vid, 0), int(f.get("trace_mark") or 0))
        return out

    def _window_core(self, con: sqlite3.Connection, exclude: Iterable[str] = (),
                     skip_rows: Iterable[tuple] = ()) -> dict[str, Any]:
        """The window anchored on evidence that is not the label under
        test: per host and account the stated starts at LIKELY or stronger,
        earliest first, from (a) inbound attacker edges, (b) attacker_from
        rows and (c) fine attacker events that drew no window note
        themselves; coarse belief-events and proposals never anchor. A
        start stated by a noted claim that stands unsupported is listed
        under "noted". "unanchored": hosts with attacker labels and no
        start of their own; they take the estate start."""
        from core.incident_window import answered_after
        exclude = {str(c) for c in exclude}
        skip = {(str(c), str(k), str(v).lower()) for c, k, v in skip_rows}
        hosts: dict[str, set] = {}
        accounts: dict[str, set] = {}
        via: dict[str, dict[tuple, str]] = {}
        noted: list[tuple[str, str, str, str]] = []
        held: dict[str, bool] = {}

        def is_held(cid: str, flag: Any, statement: str, mark: Any) -> bool:
            if not flag:
                return False
            if cid not in held:
                held[cid] = not answered_after(statement, int(mark or 0))
            return held[cid]

        src: dict[str, list] = {}

        def put(kind: str, value: str, t: str, cid: str, how: str, vid: int = 0) -> None:
            (hosts if kind == "host" else accounts).setdefault(value, set()).add((t, cid))
            src.setdefault(f"{kind}|{value}", []).append((t, cid, how))
            if kind == "host":
                via.setdefault(value, {})[(t, cid)] = how

        for r in con.execute("SELECT a.*, i.tier, i.noted, i.statement, i.noted_mark FROM anchors a JOIN ingested i "
                             "ON i.claim_id = a.claim_id WHERE i.current = 1 AND a.t != ''"):
            cid = r["claim_id"]
            if cid in exclude or r["tier"] not in _STRONG or (cid, r["kind"], r["value"].lower()) in skip:
                continue
            if is_held(cid, r["noted"], r["statement"], r["noted_mark"]):
                noted.append((r["kind"], r["value"], r["t"], cid))
                continue
            put(r["kind"], r["value"], r["t"], cid, "row")
        noted_events = self._noted_events(con)
        not_anchoring: list[int] = []
        for e in self._backed_events(con, fine_only=True):
            cid = e["by_claim"]
            if cid in exclude or e["tier"] not in _STRONG:
                continue
            dst = [self.case_host(n["display"]) for n in self._role_entities(con, e["vid"], "dst", "host")]
            accts = [self.account_id(a["key"], a["host"])
                     for a in self._role_entities(con, e["vid"], "actor", "account")]
            if not self._belief_about(con, cid, e, dst):
                # The label stands; a belief about another host or other
                # values does not move this event's window.
                not_anchoring.append(e["vid"])
                continue
            noted_now = (e["vid"] in noted_events
                         and not answered_after(e["statement"], noted_events[e["vid"]]))
            if noted_now or is_held(cid, e["noted"], e["statement"], e["noted_mark"]):
                # Held, never dropped: the earliest of every stated start
                # (evidence leave) still sees it.
                noted += [("host", h, e["t"], cid) for h in [d for d in dst if d] or [e["host"]]]
                noted += [("account", a, e["t"], cid) for a in accts]
                continue
            for h in [d for d in dst if d] or [e["host"]]:
                put("host", h, e["t"], cid, "inbound" if dst else "event", e["vid"])
            for a in accts:
                put("account", a, e["t"], cid, "event", e["vid"])
        out_hosts = {h: sorted(v) for h, v in hosts.items()}
        out_accounts = {a: sorted(v) for a, v in accounts.items()}
        starts = [v[0] for v in out_hosts.values()]
        att = (f"SELECT CAST(substr(l.target, 3) AS INTEGER) FROM labels l WHERE {_CURRENT} AND l.proposal = 0 "
               "AND l.label = 'attacker' AND l.target LIKE 'e:%'")
        labelled = {e["host"] for e in self._attacker_events(con)}
        labelled |= {r[0] for r in con.execute(
            f"SELECT host FROM entities WHERE host != '' AND eid IN ({att}) "
            f"UNION SELECT host FROM sightings WHERE entity_id IN ({att}) "
            f"UNION SELECT e.host FROM events e JOIN roles r ON r.vid = e.vid WHERE r.eid IN ({att})")}
        labelled.discard("")
        # The bounds the edge-free checks compare with: a host's stated
        # arrival (an attacker_from row or an inbound edge to it), an
        # account's stated start (attacker_from). Activity is never a bound:
        # an event later than another says nothing against it. The estate
        # fallback for a host with no bound of its own comes from
        # attacker_from rows only: initial access precedes the first
        # lateral arrival, so an inbound edge elsewhere bounds nothing here.
        bound = {k: min((t, c) for t, c, how in v if how in ("row", "inbound")) for k, v in src.items()
                 if k.startswith("host|") and any(how in ("row", "inbound") for _t, _c, how in v)}
        bound.update({k: min((t, c) for t, c, how in v if how == "row") for k, v in src.items()
                      if k.startswith("account|") and any(how == "row" for _t, _c, how in v)})
        rows = [min((t, c) for t, c, how in v if how == "row") for k, v in src.items()
                if k.startswith("host|") and any(how == "row" for _t, _c, how in v)]
        bound["estate"] = min(rows) if rows else None
        bounds = {"entity": bound, "event": bound}
        return {"_bounds": bounds,
                "hosts": out_hosts, "accounts": out_accounts, "estate": min(starts) if starts else None,
                "noted": sorted(set(noted)), "unanchored": sorted(labelled - set(out_hosts)),
                "not_anchoring": sorted(set(not_anchoring)),
                "via": {h: via[h][v[0]] for h, v in out_hosts.items()},
                }

    def _belief_about(self, con: sqlite3.Connection, cid: str, e: sqlite3.Row, dst: list[str]) -> bool:
        """Whether the belief backing an event's label is about that event:
        its host is the event's host or destination, or its typed rows hold
        one of the event's entities."""
        row = con.execute("SELECT host FROM ingested WHERE claim_id = ?", (cid,)).fetchone()
        if row and row[0] and (row[0] == e["host"] or row[0] in dst):
            return True
        return con.execute(
            "SELECT 1 FROM roles r JOIN labels l ON l.target = 'e:' || r.eid "
            "WHERE r.vid = ? AND l.claim_id = ? AND l.by = 'ingest' LIMIT 1", (e["vid"], cid)).fetchone() is not None

    @staticmethod
    def _bound(w: dict[str, Any], which: str, kind: str, key: str) -> tuple[Optional[tuple], bool]:
        """The bound a check of ``which`` (entity or event) compares with on
        a host or account, and whether it is the estate start (the
        fallback where none is stated)."""
        b = w["_bounds"][which]
        own = b.get(f"{kind}|{key}")
        if own:
            return own, False
        return (b["estate"], True) if b["estate"] else (None, False)

    def _window_checks(self, con: sqlite3.Connection, w: dict[str, Any], only: Optional[set[int]] = None,
                       only_v: Optional[set[int]] = None, *, entities: bool = True, events: bool = True) -> None:
        """seen_before_start and account_before_start, once per pair: time
        comparisons over the model's own labels and the anchored starts;
        notes and changes, never refusals. ``only`` and ``only_v``: the
        entities and events to check (all when None)."""
        from core.incident_window import trace_mark
        attackers = self._attacker_eids(con)
        for eid in attackers if entities else ():
            if only is not None and eid not in only:
                continue
            seen: dict[str, str] = {}
            for h, t in con.execute("SELECT host, t FROM sightings WHERE entity_id = ? AND t != ''", (eid,)):
                seen[h] = min(seen.get(h, t), t)
            for h, t in con.execute("SELECT e.host, e.t FROM events e JOIN roles r ON r.vid = e.vid "
                                    "WHERE r.eid = ? AND e.t != ''", (eid,)):
                seen[h] = min(seen.get(h, t), t)
            for h, t in sorted(seen.items()):
                start, fallback = self._bound(w, "entity", "host", h)
                if start and t < start[0]:
                    self._change(con, "seen_before_start", {
                        "entity_id": eid, "host": h, "time": t, "anchor": start[0], "anchor_claim": start[1],
                        "from_estate_start": fallback}, once_key=f"sbs:e{eid}:{h}" + _own(fallback))
        attacker_set = set(attackers)
        for e in self._attacker_events(con) if events else ():
            if only is not None and e["vid"] not in (only_v or set()) and not con.execute(
                    f"SELECT 1 FROM roles WHERE vid = ? AND eid IN ({','.join(map(str, only)) or '0'}) LIMIT 1",
                    (e["vid"],)).fetchone():
                continue
            start, fallback = self._bound(w, "event", "host", e["host"])
            if start and e["t"] < start[0]:
                self._change(con, "seen_before_start", {
                    "event_id": e["vid"], "host": e["host"], "time": e["t"], "anchor": start[0],
                    "anchor_claim": start[1], "from_estate_start": fallback, "trace_mark": trace_mark()},
                    once_key=f"sbs:v{e['vid']}:{e['host']}" + _own(fallback))
            for a in self._role_entities(con, e["vid"], "actor", "account"):
                aid = self.account_id(a["key"], a["host"])
                anchor, fallback = self._bound(w, "event", "account", aid)
                own = not fallback
                if fallback and a["eid"] not in attacker_set:
                    anchor = None
                if anchor and e["t"] < anchor[0]:
                    self._change(con, "account_before_start", {
                        "event_id": e["vid"], "account": a["display"], "time": e["t"], "anchor": anchor[0],
                        "anchor_claim": anchor[1], "from_estate_start": not own,
                        "trace_mark": trace_mark()}, once_key=f"abs:v{e['vid']}:{aid}" + _own(not own))

    def _inbound_hosts(self, con: sqlite3.Connection) -> set[str]:
        """Hosts an attacker event reaches from another host or an endpoint."""
        vids = ",".join(str(e["vid"]) for e in self._attacker_events(con)) or "0"
        return {self.case_host(r[0]) or r[0] for r in con.execute(
            "SELECT DISTINCT d.display FROM roles rd JOIN entities d ON d.eid = rd.eid "
            "JOIN roles rs ON rs.vid = rd.vid AND rs.role = 'src' JOIN entities x ON x.eid = rs.eid "
            f"WHERE rd.vid IN ({vids}) AND rd.role = 'dst' AND d.kind = 'host' "
            "AND x.kind IN ('host', 'endpoint') AND x.eid != d.eid")}

    # ── joins: signals, never labels ─────────────────────────────────────

    def _twins(self, con: sqlite3.Connection) -> set[int]:
        """Entities sharing a file name or a hash with what this write
        touched: their joins may have grown."""
        if not self._dirty:
            return set()
        ids = ",".join(map(str, self._dirty))
        out = {r[0] for r in con.execute(
            f"SELECT b.eid FROM entities a JOIN entities b ON b.kind = 'file' AND b.name = a.name "
            f"WHERE a.eid IN ({ids}) AND a.kind = 'file' AND a.name != ''")}
        out |= {r[0] for r in con.execute(
            f"SELECT b.eid FROM entity_hashes a JOIN entity_hashes b ON b.value = a.value WHERE a.eid IN ({ids})")}
        out |= {r[0] for r in con.execute(
            f"SELECT n.eid FROM entity_hashes h JOIN entities n ON n.kind = 'file' AND n.host = '' AND n.key = h.value "
            f"WHERE h.eid IN ({ids})")}
        return out

    def _joins(self, con: sqlite3.Connection, candidates: Iterable[int]) -> None:
        """join_hit for each host an attacker entity reaches by an equal
        hash, file name, account or endpoint (the map's other entities, the
        sightings, the contents index's listing) where no event names the
        entity, with the rarity k/n of the value (hosts holding it over the
        hosts that could). The listing is read once per entity."""
        n_case = max(1, len(self._hosts()))
        listed = set(self._meta(con, "listing_joined", []))
        for eid in sorted(candidates):
            e = con.execute("SELECT * FROM entities WHERE eid = ?", (eid,)).fetchone()
            attrs = json.loads(e["attrs"] or "{}")
            if e["kind"] in ("evidence_item", "observation", "host") or attrs.get("kind_as_typed"):
                continue
            via = {"account": "account", "endpoint": "endpoint"}.get(e["kind"]) or (
                "hash" if e["host"] == "" and any(k in attrs for k in _HASH_ATTR.values()) else "name")
            reach: dict[str, tuple[int, int]] = {}
            own = {e["host"]} | {r[0] for r in con.execute(
                "SELECT e.host FROM events e JOIN roles r ON r.vid = e.vid WHERE r.eid = ?", (eid,))}
            sighted = {r[0] for r in con.execute("SELECT DISTINCT host FROM sightings WHERE entity_id = ?", (eid,))}
            for h in sighted:
                reach[h] = (len(sighted | ({e["host"]} - {""})), n_case, "case_hosts")
            if via == "name":
                twins = {r[0] for r in con.execute("SELECT host FROM entities WHERE kind = 'file' AND name = ? "
                                                   "AND host != ''", (e["name"],))}
                for h in twins:
                    reach.setdefault(h, (len(twins), n_case, "case_hosts"))
            elif via == "hash":
                holders = {r[0] for r in con.execute(
                    "SELECT n.host FROM entity_hashes h JOIN entities n ON n.eid = h.eid "
                    "WHERE h.value = ? AND n.kind = 'file' AND n.host != ''", (e["key"],))}
                for h in holders:
                    reach.setdefault(h, (len(holders), n_case, "case_hosts"))
            if eid not in listed and via in ("name", "account"):
                listed.add(eid)
                for h, k, n in self._listing_reach(e):
                    reach.setdefault(h, (k, n, "listed_hosts"))
            for h, (k, n, n_kind) in sorted(reach.items()):
                if h and h not in own:
                    # n_kind: what n counts (the case's hosts, or the hosts
                    # the contents index lists), so a reader compares like
                    # with like.
                    self._change(con, "join_hit", {"entity_id": eid, "host": h, "via": via, "k": k, "n": n,
                                                   "n_kind": n_kind}, once_key=f"join:{eid}:{h}:{via}")
        if listed != set(self._meta(con, "listing_joined", [])):
            self._set_meta(con, "listing_joined", sorted(listed))

    def _listing_reach(self, e: sqlite3.Row) -> list[tuple[str, int, int]]:
        """Hosts whose listing holds the entity's file name or the
        account's profile folder, with k and n over the listed hosts."""
        try:
            if e["kind"] == "file":
                from core.contents_index import find_by_names
                rows = find_by_names(self.case_dir, [e["key"].rsplit("/", 1)[-1]])
                held = {self.case_host(r.get("host")) for r in rows if r.get("host")}
                listed = self._listed_hosts()
            else:
                profiles = self._profile_cache()
                held = {self.case_host(h) for h, names in profiles.items() if account_key(e["key"]) in names}
                listed = len(profiles)
        except Exception:  # noqa: BLE001 - a case without a listing joins nothing
            return []
        held.discard("")
        return [(h, len(held), max(1, listed)) for h in sorted(held)]

    def _listed_hosts(self) -> int:
        from contextlib import closing
        from core.contents_index import _connect
        con = _connect(self.case_dir)
        if con is None:
            return 0
        with closing(con):
            return int(con.execute("SELECT COUNT(DISTINCT host) FROM entries WHERE host IS NOT NULL "
                                   "AND host != ''").fetchone()[0])

    def _profile_cache(self) -> dict[str, set[str]]:
        if not hasattr(self, "_profiles"):
            from core.evidence_leave import _profiles
            self._profiles = _profiles(self.case_dir)
        return self._profiles

    # ── views: questions as tables with open rows (4.5) ──────────────────

    @staticmethod
    def view_columns(over: str) -> list[str]:
        """The column paths a view over ``over`` may name."""
        if over.startswith("event:"):
            return list(_EVENT_COLUMNS)
        return list(_HOST_COLUMNS if over == "host" else _ENTITY_COLUMNS) + ["attrs.<name>"]

    def _check_spec(self, spec: Any) -> tuple[Optional[dict[str, Any]], list[str]]:
        if not isinstance(spec, dict):
            return None, ["a view is an object with over, where and columns"]
        over = str(spec.get("over") or "")
        kind = over.split(":", 1)[1] if over.startswith("event:") else ""
        if over not in _VIEW_OVER and not (over.startswith("event:") and kind in EVENT_KINDS):
            return None, [f"over {over!r} is one of {', '.join(_VIEW_OVER)} or event:<kind> "
                          f"(kinds: {', '.join(EVENT_KINDS)})"]
        where = spec.get("where") if isinstance(spec.get("where"), dict) else {}
        if where.get("label") and where["label"] not in LABELS:
            return None, [f"where.label is one of {', '.join(LABELS)}"]
        for k in ("after", "before"):
            if where.get(k) and not _iso(where[k]):
                return None, [f"where.{k} {where[k]!r} is no time"]
        cols = [str(c) for c in spec.get("columns") or [] if str(c).strip()]
        allowed = self.view_columns(over)
        bad = [c for c in cols if c not in allowed and not (c.startswith("attrs.") and len(c) > 6
                                                            and not over.startswith("event:"))]
        if bad:
            return None, [f"unknown column(s) {', '.join(bad)}; the columns of a view over {over}: "
                          f"{', '.join(allowed)}"]
        clean = {"over": over, "where": {k: where[k] for k in ("label", "host", "after", "before") if where.get(k)},
                 "columns": cols or ["label"]}
        if clean["where"].get("host"):
            clean["where"]["host"] = self.case_host(clean["where"]["host"]) or clean["where"]["host"]
        return clean, []

    def declare_view(self, task_id: str, part_id: str, spec: Any, _by: str = "model") -> dict[str, Any]:
        """What a question part's answer ranges over, declared by the model
        (the plan reply, or a frontier item); code fills the rows. The
        newest declaration of a (task, part) is current; older ones stay
        as history. An unknown over, label or column is refused in the
        notes with what is allowed."""
        self.sync()
        clean, notes = self._check_spec(spec)
        if clean is None:
            return {"ok": False, "view_id": 0, "notes": notes}
        with self._write() as con:
            con.execute("UPDATE views SET current = 0 WHERE task_id = ? AND part_id = ?", (task_id, part_id))
            vid = int(con.execute(
                "INSERT INTO views(task_id, part_id, spec, declared_by, seq, current) VALUES (?, ?, ?, ?, ?, 1)",
                (str(task_id), str(part_id), json.dumps(clean, sort_keys=True), _by, self._seq(con))).lastrowid)
        return {"ok": True, "view_id": vid, "notes": notes}

    def _sync_parts(self, con: sqlite3.Connection, tasks: dict[str, Any]) -> None:
        """Every question part has a view: a part no declaration covers gets
        the default one, one row keyed by the part, filled when the part is
        answered or limited (its status is read from the tasks)."""
        parts: dict[str, str] = {}
        for t in tasks.get("tasks") or []:
            if not isinstance(t, dict) or not t.get("id"):
                continue
            for p in t.get("parts") or []:
                if isinstance(p, dict) and p.get("id"):
                    tid, pid = str(t["id"]), str(p["id"])
                    parts[f"{tid}|{pid}"] = str(p.get("status") or "open")
                    if not con.execute("SELECT 1 FROM views WHERE task_id = ? AND part_id = ?", (tid, pid)).fetchone():
                        con.execute("INSERT INTO views(task_id, part_id, spec, declared_by, seq, current) "
                                    "VALUES (?, ?, ?, 'default', ?, 1)",
                                    (tid, pid, json.dumps({"over": "part"}), self._seq(con)))
        self._set_meta(con, "parts", parts)

    def _cell(self, value: Any, claim: str = "", proposal: bool = False) -> dict[str, Any]:
        if proposal:
            return {"value": "proposed", "claim": claim, "open": True}
        if value in (None, ""):
            return {"value": "open", "claim": "", "open": True}
        return {"value": str(value), "claim": claim, "open": False}

    def _view_rows(self, con: sqlite3.Connection, view: sqlite3.Row, w: dict[str, Any]) -> list[dict[str, Any]]:
        """The rows of one view: one per selected entity (or event, or the
        part itself), each cell filled only from belief-backed labels and
        anchors; a proposal shows as "proposed" and counts as open."""
        spec = json.loads(view["spec"])
        over, where, cols = spec["over"], spec.get("where") or {}, spec.get("columns") or []
        if over == "part":
            st = (self._meta(con, "parts", {}) or {}).get(f"{view['task_id']}|{view['part_id']}", "open")
            cell = self._cell(st if st in ("answered", "limited") else "")
            return [{"row_key": view["part_id"], "cells": {"part": cell}, "status": "open" if cell["open"] else "filled",
                     "basis_ids": []}]
        label = where.get("label")
        rows: list[dict[str, Any]] = []
        if over.startswith("event:"):
            kind = over.split(":", 1)[1]
            for e in con.execute("SELECT * FROM events WHERE kind = ? ORDER BY t, vid", (kind,)).fetchall():
                lab, prop = self._state(con, f"v:{e['vid']}")
                if (label and lab != label) or (where.get("host") and e["host"] != where["host"]) \
                        or not self._in_bounds(e["t"], where):
                    continue
                rows.append(self._event_row(con, e, cols, lab, prop))
        else:
            for key, values, t in self._selected(con, over, where, w):
                if not self._in_bounds(t, where):
                    continue
                cells = {c: values(c) for c in cols}
                rows.append({"row_key": key, "cells": cells})
        for r in rows:
            r["status"] = "open" if any(c["open"] for c in r["cells"].values()) else "filled"
            r["basis_ids"] = sorted({c["claim"] for c in r["cells"].values() if c["claim"]})
        if not rows:
            rows = [{"row_key": "-", "cells": {c: self._cell("") for c in cols}, "status": "open", "basis_ids": []}]
        return rows

    @staticmethod
    def _in_bounds(t: str, where: dict[str, Any]) -> bool:
        after, before = _iso(where.get("after")), _iso(where.get("before"))
        if not (after or before):
            return True
        return bool(t) and (not after or t >= after) and (not before or t <= before)

    def _event_row(self, con: sqlite3.Connection, e: sqlite3.Row, cols: list[str], lab: Optional[str],
                   prop: int) -> dict[str, Any]:
        claim = next((r["claim_id"] for r in reversed(self._current_labels(con, f"v:{e['vid']}"))
                      if not r["proposal"]), "")
        backed = bool(lab) and not prop

        def role(name: str) -> str:
            return ", ".join(n["display"] for n in con.execute(
                "SELECT n.display FROM roles r JOIN entities n ON n.eid = r.eid WHERE r.vid = ? AND r.role = ? "
                "ORDER BY n.eid", (e["vid"], name)))
        values = {"time": e["t"], "host": e["host"], "verb": e["verb"] or e["kind"], "label": lab or "",
                  "actor": role("actor"), "object": role("object"), "src": role("src"), "dst": role("dst")}
        return {"row_key": f"v:{e['vid']}",
                "cells": {c: self._cell(values.get(c), claim, proposal=bool(lab) and not backed) for c in cols}}

    def _selected(self, con: sqlite3.Connection, over: str, where: dict[str, Any], w: dict[str, Any]):
        """(row key, cell function, row time) of each entity a view selects."""
        label = where.get("label")
        backed_events = self._attacker_events(con)
        if over == "host":
            labelled = sorted(set(w["hosts"]) | set(w["unanchored"]))
            hosts = labelled if label == "attacker" else []
            if label != "attacker":
                hosts = sorted({self.case_host(r["display"]) or r["display"] for r in con.execute(
                    "SELECT * FROM entities WHERE kind = 'host'") if (not label or self._state(
                        con, f"e:{r['eid']}")[0] == label)})
            if where.get("host"):
                hosts = [h for h in hosts if h == where["host"]]
            for h in hosts:
                first = next((e for e in backed_events if e["host"] == h), None)
                yield h, self._host_cells(con, h, first, w), (first["t"] if first else "")
            return
        for e in con.execute("SELECT * FROM entities WHERE kind = ? ORDER BY display, eid", (over,)).fetchall():
            lab, prop = self._state(con, f"e:{e['eid']}")
            if label and lab != label:
                continue
            hosts = self._entity_hosts(con, e["eid"])
            if where.get("host") and where["host"] not in hosts:
                continue
            first = next((v for v in backed_events if con.execute(
                "SELECT 1 FROM roles WHERE vid = ? AND eid = ?", (v["vid"], e["eid"])).fetchone()), None)
            yield (e["display"], self._entity_cells(con, e, lab, prop, hosts, first, w),
                   first["t"] if first else "")

    def _first_claim(self, con: sqlite3.Connection, ev: Optional[sqlite3.Row]) -> str:
        if ev is None:
            return ""
        return next((r["claim_id"] for r in self._current_labels(con, f"v:{ev['vid']}")
                     if not r["proposal"] and r["label"] == "attacker"), "")

    def _host_cells(self, con: sqlite3.Connection, h: str, first: Optional[sqlite3.Row], w: dict[str, Any]):
        own = w["hosts"].get(h)
        inbound = None
        for e in self._attacker_events(con):
            dst = [self.case_host(n["display"]) for n in self._role_entities(con, e["vid"], "dst", "host")]
            src = (self._role_entities(con, e["vid"], "src", "host")
                   + self._role_entities(con, e["vid"], "src", "endpoint"))
            if h in dst and any((self.case_host(s["display"]) or s["display"]) != h for s in src):
                inbound = (e, src)
                break
        fclaim = self._first_claim(con, first)
        iclaim = self._first_claim(con, inbound[0]) if inbound else ""

        def cell(c: str) -> dict[str, Any]:
            if c == "label":
                return self._cell("attacker" if first or own else "", fclaim or (own[0][1] if own else ""))
            if c.startswith("first_attacker_event."):
                f = c.split(".", 1)[1]
                v = {"time": first["t"], "verb": first["verb"] or first["kind"], "host": first["host"],
                     "claim": fclaim}.get(f) if first else ""
                return self._cell(v, fclaim)
            if c.startswith("start."):
                f = c.split(".", 1)[1]
                if not own:
                    return self._cell("")
                return self._cell({"time": own[0][0], "via": w["via"].get(h, "row"), "claim": own[0][1]}.get(f),
                                  own[0][1])
            if c.startswith("inbound."):
                if not inbound:
                    return self._cell("")
                e, src = inbound
                f = c.split(".", 1)[1]
                v = {"time": e["t"], "verb": e["verb"] or e["kind"],
                     "src": ", ".join(s["display"] for s in src),
                     "actor": ", ".join(a["display"] for a in self._role_entities(con, e["vid"], "actor", "account"))
                     }.get(f)
                return self._cell(v, iclaim)
            return self._cell("")
        return cell

    def _entity_cells(self, con: sqlite3.Connection, e: sqlite3.Row, lab: Optional[str], prop: int,
                      hosts: list[str], first: Optional[sqlite3.Row], w: dict[str, Any]):
        attrs = json.loads(e["attrs"] or "{}")
        claim = next((r["claim_id"] for r in reversed(self._current_labels(con, f"e:{e['eid']}"))
                      if not r["proposal"]), "")
        fclaim = self._first_claim(con, first)
        aid = self.account_id(e["key"], e["host"]) if e["kind"] == "account" else ""
        own = w["accounts"].get(aid) if aid else None

        def cell(c: str) -> dict[str, Any]:
            if prop:
                return self._cell("", claim, proposal=True)
            if c == "label":
                return self._cell(lab, claim)
            if c == "hosts":
                return self._cell(", ".join(hosts), claim)
            if c.startswith("first_attacker_event."):
                f = c.split(".", 1)[1]
                v = {"time": first["t"], "verb": first["verb"] or first["kind"], "host": first["host"],
                     "claim": fclaim}.get(f) if first else ""
                return self._cell(v, fclaim)
            if c.startswith("start."):
                if not own:
                    return self._cell("")
                return self._cell({"time": own[0][0], "claim": own[0][1]}.get(c.split(".", 1)[1]), own[0][1])
            if c.startswith("attrs."):
                return self._cell(attrs.get(c[6:]), claim)
            return self._cell("")
        return cell

    def _all_views(self, con: sqlite3.Connection, open_only: bool = False) -> list[dict[str, Any]]:
        w = self._window_core(con)
        out = []
        for v in con.execute("SELECT * FROM views WHERE current = 1 ORDER BY task_id, part_id, view_id").fetchall():
            rows = self._view_rows(con, v, w)
            if open_only:
                rows = [r for r in rows if r["status"] == "open"]
                if not rows:
                    continue
            out.append({"view_id": v["view_id"], "task_id": v["task_id"], "part_id": v["part_id"],
                        "spec": json.loads(v["spec"]), "declared_by": v["declared_by"], "rows": rows})
        return out

    def _derive_views(self, con: sqlite3.Connection) -> None:
        """view_row_opened and view_row_filled when a row appears open, or a
        row's status changes; recomputed only when a label, an event, a
        start, a view or a part status changed."""
        sig = [con.execute("SELECT COALESCE(MAX(lid), 0) FROM labels").fetchone()[0],
               con.execute("SELECT COALESCE(MAX(vid), 0) FROM events").fetchone()[0],
               con.execute("SELECT COALESCE(MAX(view_id), 0) FROM views").fetchone()[0],
               self._meta(con, "starts", {}), self._meta(con, "parts", {}),
               con.execute("SELECT COUNT(*) FROM ingested WHERE current = 1").fetchone()[0],
               con.execute("SELECT COUNT(*) FROM roles").fetchone()[0]]
        if self._meta(con, "views_sig") == sig:
            return
        old = self._meta(con, "view_rows", {})
        now: dict[str, str] = {}
        parts = {r["view_id"]: (r["task_id"], r["part_id"]) for r in con.execute("SELECT * FROM views")}
        for v in self._all_views(con):
            for r in v["rows"]:
                k = f"{v['view_id']}|{r['row_key']}"
                now[k] = r["status"]
                if old.get(k) != r["status"]:
                    kind = "view_row_opened" if r["status"] == "open" else "view_row_filled"
                    self._change(con, kind, {"view_id": v["view_id"], "task_id": v["task_id"],
                                             "part_id": v["part_id"], "row_key": r["row_key"]})
        for k in sorted(set(old) - set(now)):
            # The row left its view (its value lost the label, or the view
            # was declared anew): its items go moot.
            vid, _, row_key = k.partition("|")
            task, part = parts.get(int(vid), ("", ""))
            self._change(con, "view_row_closed", {"view_id": int(vid), "task_id": task, "part_id": part,
                                                  "row_key": row_key, "gone": True})
        self._set_meta(con, "view_rows", now)
        self._set_meta(con, "views_sig", sig)

    def views(self, open_only: bool = False) -> list[dict[str, Any]]:
        """The current view of every question part with its rows
        ({row_key, status open|filled, cells, basis_ids}); ``open_only``
        keeps the open rows."""
        self.sync()
        with self._read() as con:
            return self._all_views(con, open_only)

    # ── basis rows ───────────────────────────────────────────────────────

    @staticmethod
    def _entry(call_id: int) -> Optional[dict[str, Any]]:
        try:
            from core.execution_log import log
            e = (log.index().by_call_id or {}).get(int(call_id))
            return e if isinstance(e, dict) else None
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _rows(entry: dict[str, Any]) -> tuple[str, list[Any]]:
        from core.indicators import SPILL_READ_CHARS, _output_text, _rows_of
        raw = _output_text(entry, SPILL_READ_CHARS)
        return raw, _rows_of(entry, raw)[0]

    @staticmethod
    def _row_fold(row: Any) -> str:
        if isinstance(row, str):
            return _fold(row)
        return _fold(json.dumps(row, ensure_ascii=False, default=str).replace("\\\\", "\\"))

    def row_ref_for(self, call_id: int, quote: str) -> Optional[str]:
        """``"<call_id>#R<i>"`` for the i-th row (from 1) of a JSON row array
        holding the quote (whitespace folded), ``"<call_id>#L<n>"`` for the
        n-th line of text or a table; the first match; None when the call's
        saved output does not hold it. Read echo-free (core.indicators
        ._rows_of: what the call was given and echoes back is no row), and a
        quote that lies inside one of the call's own argument values is
        none: a search's pattern is the analyst's words, never evidence."""
        return self._match(call_id, [quote], whole=True)

    def row_ref_for_cells(self, call_id: int, cells: Iterable[str]) -> Optional[str]:
        """The first row (or line) of a call's saved output that holds every
        one of ``cells`` (whitespace folded): a quote of a rendered view of
        the output (a table line with its cells joined) mapped back to the
        row it shows. Echo-free as row_ref_for; cells that all lie inside
        the call's own argument values name no row. None when no row holds
        them all."""
        return self._match(call_id, list(cells), whole=False)

    def _match(self, call_id: int, parts: list[str], whole: bool) -> Optional[str]:
        from core.indicators import request_strings
        entry = self._entry(call_id)
        want = [c for c in (_fold(x).replace("\\\\", "\\") for x in parts) if c]
        if not entry or not want:
            return None
        asked = [_fold(r).replace("\\\\", "\\") for r in request_strings(entry)]
        if all(any(c in a for a in asked) for c in want):
            return None                                   # the call's own arguments, echoed
        raw, rows = self._rows(entry)
        structured = raw.lstrip()[:1] in "{["
        lines = [_fold(ln).replace("\\\\", "\\") for ln in raw.splitlines()]
        refs = self._match_all(call_id, rows, raw, want, structured, lines)
        return refs[0] if refs else None

    def _match_all(self, call_id: int, rows: list, raw: str, want: list[str], structured: bool,
                   lines: list[str]) -> list[str]:
        """Every row (or line) holding all of ``want``: a structured output's
        rows by their place (its string rows too: a JSON list of lines is
        rows, never one line of escaped JSON text), a text's by its line."""
        out = []
        for i, r in enumerate(rows, 1):
            text = self._row_fold(r).replace("\\\\", "\\")
            if not all(c in text for c in want):
                continue
            if structured:
                out.append(f"{int(call_id)}#R{i}")
                continue
            n = next((k for k, ln in enumerate(lines, 1) if text and text in ln), 0)
            if n:
                out.append(f"{int(call_id)}#L{n}")
        return list(dict.fromkeys(out))

    # ponytail: the newest 100 calls, 128 KB each, for a refusal's wording only;
    # an index of saved outputs if a run needs the whole trace searched.
    _HOLDING_CALLS = 100
    _HOLDING_CHARS = 128_000

    def call_holding(self, quote: str, exclude: set, texts: dict | None = None) -> int:
        """The newest tool call of the run (outside ``exclude``) whose saved
        output holds the quote, in either encoding; 0 when none of the
        newest calls does. Only what a refusal says depends on it, so an
        output that cannot be read is passed over, never raised. ``texts``:
        the folded outputs already read (the caller keeps them for one
        submit, so its refusals read each output once)."""
        texts = {} if texts is None else texts
        try:
            from core.execution_log import log
            from core.indicators import _output_text
            entries = log.index().by_call_id or {}
            want = _fold(re.sub(r"\\+", lambda _m: "\\", str(quote or ""))).replace('\\"', '"')
            ids = sorted((int(c) for c, e in entries.items() if isinstance(e, dict) and e.get("type") == "tool_call"
                          and int(c) not in exclude), reverse=True)[:self._HOLDING_CALLS]
        except Exception:  # noqa: BLE001
            return 0
        if len(want) < 12:
            return 0
        for c in ids:
            if c not in texts:
                try:
                    texts[c] = _fold(re.sub(r"\\+", lambda _m: "\\", _output_text(entries[c], self._HOLDING_CHARS))
                                     ).replace('\\"', '"')
                except Exception:  # noqa: BLE001 - an output that cannot be read holds nothing here
                    texts[c] = ""
            if want in texts[c]:
                return c
        return 0

    def row_refs_for(self, call_id: int, quote: str) -> list[str]:
        """Every row of a call's saved output that holds the whole quote, as
        row_ref_for finds the first (echo-free)."""
        from core.indicators import request_strings
        entry = self._entry(call_id)
        want = [c for c in (_fold(quote).replace("\\\\", "\\"),) if c]
        if not entry or not want:
            return []
        asked = [_fold(r).replace("\\\\", "\\") for r in request_strings(entry)]
        if all(any(c in a for a in asked) for c in want):
            return []
        raw, rows = self._rows(entry)
        lines = [_fold(ln).replace("\\\\", "\\") for ln in raw.splitlines()]
        return self._match_all(call_id, rows, raw, want, raw.lstrip()[:1] in "{[", lines)

    def row_ref_for_time(self, call_id: int, times: Iterable[str],
                         cells: Iterable[str] = ()) -> tuple[Optional[str], int]:
        """The one row of a call's saved output that holds each of ``times``
        (a rendered view's time: compared in the one normal form the view
        renders, core.table_rows' parser, so a "T", a "Z", fractions or an
        offset on the saved side read the same) and every one of ``cells``;
        (row ref, 1). Several rows, or none: (None, how many). A time no
        saved value parses to never matches."""
        entry = self._entry(call_id)
        want_t = [t for t in (_iso(x) for x in times) if t]
        want_c = [c for c in (_fold(x).replace("\\\\", "\\") for x in cells) if c]
        if not entry or not want_t:
            return None, 0
        raw, rows = self._rows(entry)
        structured = raw.lstrip()[:1] in "{["
        lines = [_fold(ln).replace("\\\\", "\\") for ln in raw.splitlines()]
        hits: list[str] = []
        for i, r in enumerate(rows, 1):
            values = [str(v) for v in r.values() if isinstance(v, (str, int, float))] if isinstance(r, dict) else \
                _TIME_IN_TEXT_RE.findall(str(r))
            moments = {m for m in (_iso(v) for v in values) if m}
            text = self._row_fold(r).replace("\\\\", "\\")
            if not all(t in moments for t in want_t) or not all(c in text for c in want_c):
                continue
            if structured:
                hits.append(f"{int(call_id)}#R{i}")
            else:
                n = next((k for k, ln in enumerate(lines, 1) if text and text in ln), 0)
                if n:
                    hits.append(f"{int(call_id)}#L{n}")
        hits = list(dict.fromkeys(hits))
        return (hits[0], 1) if len(hits) == 1 else (None, len(hits))

    def rows_for_ordinals(self, call_id: int, ordinals: list[int], first: str, last: str) -> list[str]:
        """The saved rows of a call that a collapsed view line names: its
        "#n" ordinals through the view's own record of them (the trace
        entry's view_ordinals), in ordinal order; the refs only when every
        ordinal is known and the line's first and last time are times of its
        first and last member (compared in the view's time form). [] when it
        does not verify."""
        entry = self._entry(call_id)
        marks = (entry or {}).get("view_ordinals") or {}
        if not entry or not ordinals or any(str(o) not in marks for o in ordinals):
            return []
        raw, rows = self._rows(entry)
        structured = raw.lstrip()[:1] in "{["
        by_id = {}
        for i, r in enumerate(rows):
            if isinstance(r, dict):
                by_id.setdefault(str(r.get("_row", i)), i)
        idx = [by_id.get(str(marks[str(o)])) for o in sorted(ordinals)]
        if not structured or any(i is None for i in idx):
            return []

        def moments(r: Any) -> set[str]:
            # The row's time as the view renders it (its time columns read
            # together, a date and a time column included), and any value
            # that is a time on its own.
            from core.table_rows import record_moment
            out = {m for m in (_iso(v) for v in r.values() if isinstance(v, (str, int, float))) if m}
            try:
                whole = record_moment({k: v for k, v in r.items() if not str(k).startswith("_")})
            except Exception:  # noqa: BLE001
                whole = ""
            return out | ({whole} if whole else set())
        if _iso(first) not in moments(rows[idx[0]]) or _iso(last) not in moments(rows[idx[-1]]):
            return []
        return [f"{int(call_id)}#R{i + 1}" for i in idx]

    def marker_rows(self, call_id: int) -> dict[str, tuple[str, bool]]:
        """The saved row each "#n" line of a call's rendered view shows,
        through the view's own record of it (core.tool_result_view):
        {n: (row ref, exact)}. A table view's record (view_ordinals) names
        each row by its id ("_row": exact) or, for rows without one, by its
        place in the result; a line view's (view_row_ids, string rows) "#n"
        is the n-th result line. A place is not exact: the caller checks the
        shown line against the row. {} when the call has no view record."""
        entry = self._entry(call_id)
        marks = (entry or {}).get("view_ordinals")
        ids = (entry or {}).get("view_row_ids")
        if not entry or not (isinstance(marks, dict) or isinstance(ids, list)):
            return {}
        raw, rows = self._rows(entry)
        if raw.lstrip()[:1] not in "{[":
            return {}
        out: dict[str, tuple[str, bool]] = {}
        if isinstance(marks, dict):
            by_id: dict[str, tuple[int, bool]] = {}
            for i, r in enumerate(rows):
                if isinstance(r, dict):
                    by_id.setdefault(str(r.get("_row", i)), (i, "_row" in r))
            for n, rid in marks.items():
                hit = by_id.get(str(rid))
                if hit:
                    out[str(n)] = (f"{int(call_id)}#R{hit[0] + 1}", hit[1])
            return out
        for n in ids:
            if isinstance(n, int) and 0 < n <= len(rows) and isinstance(rows[n - 1], str):
                out[str(n)] = (f"{int(call_id)}#R{n}", False)
        return out

    def row_text(self, ref: str) -> Optional[str]:
        """The full text of the row a reference names ("<call>#R<i>" or
        "<call>#L<n>"), as the saved output holds it; None when unknown."""
        try:
            cid, part = str(ref).split("#", 1)
            i = int(part[1:])
        except ValueError:
            return None
        entry = self._entry(int(cid))
        if not entry:
            return None
        raw, rows = self._rows(entry)
        if part[:1] == "R" and 0 < i <= len(rows):
            r = rows[i - 1]
            return r if isinstance(r, str) else json.dumps(r, ensure_ascii=False, default=str)
        lines = raw.splitlines()
        if part[:1] == "L" and 0 < i <= len(lines):
            return lines[i - 1]
        return None

    def _row_text(self, entry: dict[str, Any], ref: str) -> Optional[str]:
        part = ref.split("#", 1)[-1]
        try:
            i = int(part[1:])
        except ValueError:
            return None
        raw, rows = self._rows(entry)
        if part[:1] == "R" and 0 < i <= len(rows):
            return self._row_fold(rows[i - 1])
        lines = raw.splitlines()
        if part[:1] == "L" and 0 < i <= len(lines):
            return _fold(lines[i - 1])
        return None

    def _basis_notes(self, basis: Iterable[Any], values: Iterable[str], t: str = "") -> tuple[list[int], list[str]]:
        """The basis call ids and the notes on them: a call not in the
        trace, a call that read no evidence, a row that shows none of the
        values or the time. Notes only, never a refusal."""
        from core.forensic_citation import citation_class
        ids: list[int] = []
        notes: list[str] = []
        wanted = [_fold(v) for v in values if v]
        for b in basis or ():
            b = b if isinstance(b, dict) else {"call_id": b}
            try:
                cid = int(b.get("call_id"))
            except (TypeError, ValueError):
                notes.append(f"basis {b!r} names no call id")
                continue
            ids.append(cid)
            entry = self._entry(cid)
            if not entry:
                notes.append(f"call {cid} is not in the trace")
                continue
            if citation_class(entry) != "evidence":
                notes.append(f"call {cid} read no evidence")
            ref = str(b.get("row_ref") or "")
            if not ref:
                notes.append(f"basis call {cid} names no row (row_ref_for finds it from a quote)")
                continue
            text = self._row_text(entry, ref)
            if text is None:
                notes.append(f"row {ref} is not in the output of call {cid}")
            elif not (any(w in text for w in wanted) or (t and t[:10] in text and t[11:16] in text)):
                notes.append(f"row {ref} shows none of: {', '.join(list(values)[:4]) or 'the value'}"
                             + (f" or {t}" if t else ""))
        return ids, notes

    # ── public writes (4.1) ──────────────────────────────────────────────

    def upsert_entity(self, kind: str, value: str, host: str = "", attrs: dict[str, Any] | None = None) -> int:
        self.sync()
        with self._write() as con:
            return self._upsert(con, kind, value, host, attrs)

    def _entity_ok(self, con: sqlite3.Connection, eid: Any) -> Optional[sqlite3.Row]:
        try:
            return con.execute("SELECT * FROM entities WHERE eid = ?", (int(eid),)).fetchone()
        except (TypeError, ValueError):
            return None

    def add_event(self, host: str, time: str, kind: str, actor: Any = None, object: Any = None,  # noqa: A002
                  basis: Iterable[Any] = (), src: Any = None, dst: Any = None, verb: str = "") -> dict[str, Any]:
        self.sync()
        h, t = self.case_host(host), _iso(time)
        if not h:
            return {"ok": False, "event_id": 0,
                    "notes": [f"{host!r} is not a case host (one of {', '.join(self._hosts())})"]}
        if not t:
            return {"ok": False, "event_id": 0, "notes": [f"the time {time!r} does not parse"]}
        notes: list[str] = []
        if kind not in EVENT_KINDS:
            notes.append(f"kind {kind!r} is stored as other with that verb (kinds: {', '.join(EVENT_KINDS)})")
            verb, kind = verb or str(kind), "other"
        with self._write() as con:
            ents: list[tuple[int, str]] = []
            for role, eid in (("actor", actor), ("object", object), ("src", src), ("dst", dst)):
                if eid in (None, "", 0):
                    continue
                e = self._entity_ok(con, eid)
                if not e:
                    return {"ok": False, "event_id": 0, "notes": [f"no entity {eid} for {role}"]}
                ents.append((int(e["eid"]), role))
            values = [r["display"] for r in (self._entity_ok(con, e) for e, _ in ents) if r]
            ids, bnotes = self._basis_notes(basis, values, t)
            # The same event written again (host, time, kind, verb and roles)
            # is the one already in the map, its basis one source more; a
            # repeat is never new state.
            want = sorted(ents)
            for row in con.execute("SELECT vid, source FROM events WHERE host = ? AND t = ? AND kind = ? AND verb = ? "
                                   "AND claim_id = ''", (h, t, kind, verb)).fetchall():
                have = sorted((int(r[0]), str(r[1])) for r in con.execute(
                    "SELECT eid, role FROM roles WHERE vid = ?", (row["vid"],)))
                if have != want:
                    continue
                src = json.loads(row["source"] or "{}") if str(row["source"] or "").startswith("{") else {}
                merged = list(src.get("basis") or [])
                merged += [b for b in json.loads(json.dumps(list(basis or ()), default=str)) if b not in merged]
                con.execute("UPDATE events SET source = ? WHERE vid = ?",
                            (json.dumps({**src, "basis": merged}, default=str), row["vid"]))
                return {"ok": True, "event_id": int(row["vid"]), "existing": True,
                        "notes": notes + bnotes + ["the event is already in the map; its basis was added"]}
            vid = int(con.execute(
                "INSERT INTO events(kind, verb, t, t_end, host, source, claim_id, created_seq) "
                "VALUES (?, ?, ?, '', ?, ?, '', ?)",
                (kind, verb, t, h, json.dumps({"basis": list(basis or ())}, default=str), self._seq(con))).lastrowid)
            for eid, role in ents:
                con.execute("INSERT OR IGNORE INTO roles VALUES (?, ?, ?)", (vid, eid, role))
                self._dirty.add(eid)
            self._dirty_v.add(vid)
        return {"ok": True, "event_id": vid, "notes": notes + bnotes}

    def add_observation(self, text: str, host: str | None = None, time: str | None = None,
                        basis: Iterable[Any] = ()) -> dict[str, Any]:
        self.sync()
        body = " ".join(str(text or "").split())
        if not body:
            return {"ok": False, "entity_id": 0, "notes": ["an observation has text"]}
        h = self.case_host(host) if host else ""
        if host and not h:
            return {"ok": False, "entity_id": 0, "notes": [f"{host!r} is not a case host"]}
        t = _iso(time) if time else ""
        if time and not t:
            return {"ok": False, "entity_id": 0, "notes": [f"the time {time!r} does not parse"]}
        basis = list(basis or ())
        ids, notes = self._basis_notes(basis, [body[:80]], t)
        quotes = [" ".join(str(b.get("quote") or "").split())[:300] for b in basis
                  if isinstance(b, dict) and str(b.get("quote") or "").strip()][:3]
        key = hashlib.sha1(body.encode("utf-8")).hexdigest()[:16]
        with self._write() as con:
            eid = self._upsert(con, "observation", key, h, {"text": body, "t": t, "call_ids": ids, "quotes": quotes},
                               display=body[:120])
        return {"ok": True, "entity_id": eid, "notes": notes}

    def label(self, ref: str, label: str, basis: Iterable[Any] = (), note: str = "",
              claim_id: str = "", _by: str = "model") -> dict[str, Any]:
        self.sync()
        if label not in LABELS:
            return {"ok": False, "notes": [f"label {label!r} is one of {', '.join(LABELS)}"]}
        ref = str(ref or "")
        with self._write() as con:
            try:
                kind, num = ref.split(":", 1)
                table, col = {"e": ("entities", "eid"), "v": ("events", "vid")}[kind]
                found = con.execute(f"SELECT 1 FROM {table} WHERE {col} = ?", (int(num),)).fetchone()
            except (ValueError, KeyError):
                found = None
            if not found:
                return {"ok": False, "notes": [f"no target {ref!r} (e:<entity id> or v:<event id>)"]}
            values: list[str] = []
            if kind == "e":
                values = [con.execute("SELECT display FROM entities WHERE eid = ?", (int(num),)).fetchone()[0]]
            ids, notes = self._basis_notes(basis, values)
            before = {ref: self._state(con, ref)}
            proposal = self._put_label(con, ref, label, str(claim_id or ""), ids, note, _by)
            self._emit_labels(con, before)
        if proposal:
            notes.append("no current belief backs this label: it is kept as a proposal and counts as "
                         "established only once a recorded finding cites it")
        return {"ok": True, "notes": notes}

    def add_sighting(self, entity_id: int, host: str, source: str, call_id: int,
                     time: str | None = None) -> dict[str, Any]:
        self.sync()
        h = self.case_host(host)
        if not h:
            return {"ok": False, "notes": [f"{host!r} is not a case host"]}
        with self._write() as con:
            if not self._entity_ok(con, entity_id):
                return {"ok": False, "notes": [f"no entity {entity_id}"]}
            self._sight(con, int(entity_id), h, str(source or ""), int(call_id or 0), _iso(time) if time else "")
        return {"ok": True, "notes": []}

    def add_sightings(self, rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
        """Many sightings ({entity_id, host, source, call_id, time}) in one
        transaction with one derive: a code sweep's hits at the cost of one
        write. Rows that cannot be stored are named in the notes."""
        self.sync()
        notes: list[str] = []
        stored = 0
        with self._write() as con:
            for i, r in enumerate(rows):
                h = self.case_host(r.get("host"))
                if not h or not self._entity_ok(con, r.get("entity_id")):
                    notes.append(f"row {i}: no case host {r.get('host')!r} or no entity {r.get('entity_id')}")
                    continue
                t = r.get("time")
                self._sight(con, int(r["entity_id"]), h, str(r.get("source") or ""), int(r.get("call_id") or 0),
                            _iso(t) if t else "")
                stored += 1
        return {"ok": True, "stored": stored, "notes": notes}

    def _host_path(self, host: str) -> str:
        """The evidence path the Evidence Links give a host (its first)."""
        try:
            from core.evidence_links import load_evidence_links
            data = load_evidence_links(self.case_dir)
        except Exception:  # noqa: BLE001
            return ""
        for e in (data.get("entries") or []) + (data.get("links") or []):
            if isinstance(e, dict) and self.case_host(e.get("label") or e.get("host")) == host and e.get("path"):
                return str(e["path"])
        return ""

    def host_join_items(self, log, hosts: Iterable[str]) -> list[dict[str, Any]]:
        """One work item per host of ``hosts`` that a specific join reaches
        from a current attacker entity (see feed_work_items)."""
        from core.contents_index import is_specific
        from core.execution_log import _touched
        attackers = {e["entity_id"]: e for e in self.attacker_entities()}
        hosts = set(hosts)
        with self._read() as con:
            joins: dict[str, set] = {}
            for (fields,) in con.execute("SELECT fields FROM changes WHERE kind = 'join_hit'"):
                f = json.loads(fields)
                e = attackers.get(f.get("entity_id"))
                if f.get("host") in hosts and e and is_specific(f["k"], f["n"]):
                    joins.setdefault(f["host"], set()).add(
                        (f["k"] / max(1, f["n"]), f["k"], f["n"], e["kind"], e["value"], f["via"]))
            evented = {e["host"] for e in self._attacker_events(con)}
        made = []
        for h in sorted(joins):
            ranked = sorted(joins[h])
            shown = "; ".join(f"{kind} {value} by {via} ({k} of {n} hosts)" for _r, k, n, kind, value, via in ranked[:6])
            why = (f"attacker values reach {h} and no event names them there: {shown}"
                   + (f"; and {len(ranked) - 6} more" if len(ranked) > 6 else ""))
            path = self._host_path(h)
            target = {"host": h, "path": path} if path else {"host": h, "source_hint": h}
            ref = {"kind": "join_hit", "host": h, "rarity": ranked[0][0], "values": len(ranked)}
            item = log.add_work_item("join_hit", [], "", target, why,
                                     status="due" if path and h not in evented else "proposed", source_ref=ref)
            if item.get("status") in ("due", "proposed") and item.get("why") != why[:400]:
                with log._lock:
                    item["why"], item["source_ref"] = why[:400], ref
                    _touched(item)
                    log._index_version += 1
                    log._flush()
            made.append(item)
        return made

    # ── reads ────────────────────────────────────────────────────────────

    def _attacker_eids(self, con: sqlite3.Connection, proposals: bool = False) -> list[int]:
        targets = [r[0] for r in con.execute(
            f"SELECT DISTINCT l.target FROM labels l WHERE {_CURRENT} "
            + ("" if proposals else "AND l.proposal = 0 ") + "AND l.label = 'attacker' AND l.target LIKE 'e:%'")]
        return sorted(int(t[2:]) for t in targets)

    def row_hosts(self, view_id: Any, keys: Iterable[str]) -> dict[str, list[str]]:
        """The hosts each row of a view stands on: a host row its host, an
        event row its event's host, an entity row the hosts the map holds it
        on; a row the map places on no host has none."""
        view = next((v for v in self.views() if v["view_id"] == view_id), None)
        if view is None:
            return {}
        over = str((view.get("spec") or {}).get("over") or "")
        out: dict[str, list[str]] = {}
        with self._read() as con:
            for k in [str(x) for x in keys]:
                if over == "host":
                    out[k] = [self.case_host(k) or k]
                elif k.startswith("v:") and k[2:].isdigit():
                    r = con.execute("SELECT host FROM events WHERE vid = ?", (int(k[2:]),)).fetchone()
                    out[k] = [r[0]] if r and r[0] else []
                elif over and over != "part":
                    hosts: set[str] = set()
                    for e in con.execute("SELECT eid FROM entities WHERE kind = ? AND display = ?", (over, k)):
                        hosts |= set(self._entity_hosts(con, e[0]))
                    out[k] = sorted(hosts)
                else:
                    out[k] = []
        return out

    def _entity_hosts(self, con: sqlite3.Connection, eid: int) -> list[str]:
        hosts = {r[0] for r in con.execute("SELECT host FROM entities WHERE eid = ? AND host != ''", (eid,))}
        hosts |= {r[0] for r in con.execute("SELECT host FROM sightings WHERE entity_id = ?", (eid,))}
        hosts |= {r[0] for r in con.execute(
            "SELECT e.host FROM events e JOIN roles r ON r.vid = e.vid WHERE r.eid = ?", (eid,))}
        return sorted(h for h in hosts if h)

    def early_holds(self, early: dict[str, Any]) -> tuple[bool, str]:
        """Whether an early sighting a followup carries still holds: its
        entity (by its kind and value, so a merged or re-keyed entity is
        the same one) or its event is still labelled the attacker's, and
        its time is still before the host's current bound (its own start,
        else the estate start). (True, "") when it holds or its identity
        cannot be settled; (False, what changed) when it no longer does."""
        self.sync()
        host, t = str(early.get("host") or ""), str(early.get("time") or "")
        with self._read() as con:
            w = self._window_core(con, set(), [])
            which = "entity"
            if early.get("entity_id") is not None:
                row = con.execute("SELECT kind, key, display FROM entities WHERE eid = ?",
                                  (int(early["entity_id"]),)).fetchone()
                kind = str(early.get("kind") or (row["kind"] if row else ""))
                key = str(row["key"] if row else early.get("value") or "")
                same = [r["eid"] for r in con.execute("SELECT eid FROM entities WHERE kind = ? AND key = ?",
                                                      (kind, key))] if kind and key else []
                if not same:
                    return True, ""                           # identity not settled: kept
                if not set(same) & set(self._attacker_eids(con)):
                    lab = con.execute(
                        "SELECT l.label FROM labels l WHERE l.target IN (%s) AND %s AND l.proposal = 0 "
                        "ORDER BY l.lid DESC LIMIT 1" % (",".join(f"'e:{e}'" for e in same), _CURRENT)).fetchone()
                    name = str(early.get("value") or (row["display"] if row else key))
                    return False, f"{name} was the attacker's, now {lab['label'] if lab else 'unlabelled'}"
            elif early.get("event_id") is not None:
                which = "event"
                vid = int(early["event_id"])
                if con.execute("SELECT 1 FROM events WHERE vid = ?", (vid,)).fetchone() is None:
                    return True, ""
                if vid not in {e["vid"] for e in self._attacker_events(con)}:
                    return False, f"event {vid} was the attacker's, now not"
            if host and t and early.get("account") is None:
                start, fallback = self._bound(w, which, "host", host)
                if not start or t >= start[0]:
                    return False, (f"{t} was before {early.get('anchor')}, now "
                                   + (f"{host}'s {'estate' if fallback else 'own'} start is {start[0]}" if start
                                      else f"{host} has no start"))
        return True, ""

    def attacker_entities(self, proposals: bool = False) -> list[dict[str, Any]]:
        """Entities a current belief labels attacker, with the hosts they
        are on (their own host, sightings and events); with ``proposals``
        also those only a proposal labels (the conservative reading, for
        what must not be left unexamined)."""
        self.sync()
        with self._read() as con:
            out = []
            for eid in self._attacker_eids(con, proposals):
                e = con.execute("SELECT * FROM entities WHERE eid = ?", (eid,)).fetchone()
                out.append({"entity_id": eid, "kind": e["kind"], "value": e["display"],
                            "hosts": self._entity_hosts(con, eid)})
            return out

    def changes_since(self, cursor: int = 0) -> tuple[list[dict[str, Any]], int]:
        """The changes after ``cursor``, in order, as {seq, kind, ts,
        fields}, and the new cursor; the feed is append-only, so the same
        cursor gives the same list."""
        self.sync()
        with self._read() as con:
            rows = con.execute("SELECT * FROM changes WHERE seq > ? ORDER BY seq", (int(cursor or 0),)).fetchall()
        out = [{"seq": r["seq"], "kind": r["kind"], "ts": r["ts"], "fields": json.loads(r["fields"])} for r in rows]
        return out, (out[-1]["seq"] if out else int(cursor or 0))

    def head(self) -> int:
        self.sync()
        with self._read() as con:
            return self._seq(con)

    def _decision_state(self, con: sqlite3.Connection) -> dict[str, Any]:
        labels = sorted((r["target"], r["label"], r["claim_id"], r["proposal"]) for r in con.execute(
            f"SELECT l.* FROM labels l WHERE {_CURRENT}"))
        pending = sorted(k for k, v in (self._meta(con, "ledger_states", {}) or {}).items()
                         if (v[0] if isinstance(v, list) else v) == "pending")
        w = self._window_core(con)
        anchors = {"hosts": {h: v[0] for h, v in w["hosts"].items()},
                   "accounts": {a: v[0] for a, v in w["accounts"].items()}, "estate": w["estate"]}
        rows = sorted((self._meta(con, "view_rows", {}) or {}).items())
        return {"labels": labels, "attacker": self._attacker_eids(con), "pending": pending, "anchors": anchors,
                "view_rows": rows}

    def fingerprint(self) -> str:
        """A sha256 over the decision state only (current labels, the
        attacker set, the window anchors, the view rows' statuses, the
        pending ledger units);
        sightings, observations,
        label history and sequence numbers leave it unchanged."""
        self.sync()
        with self._read() as con:
            state = self._decision_state(con)
        return hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()

    def note_text(self, change: dict[str, Any]) -> str:
        """A change in plain words for a tool result; "" for kinds that are
        not notes (an event leading before its window is the window note's)."""
        f, kind = change.get("fields") or {}, change.get("kind")
        where = (f"the estate start {f.get('anchor')} ({f.get('anchor_claim')}), no start stated for {f.get('host')}"
                 if f.get("from_estate_start") else f"{f.get('anchor')} ({f.get('anchor_claim')})")
        if kind == "seen_before_start" and f.get("entity_id"):
            with self._read() as con:
                e = con.execute("SELECT kind, display FROM entities WHERE eid = ?", (f["entity_id"],)).fetchone()
            if not e:
                return ""
            return (f"{e['kind']} {e['display']} is labelled the attacker's and shows on {f['host']} at {f['time']}, "
                    f"before the attacker's first activity there: {where}. Say why it is the attacker's there, "
                    "or record it as the owner's activity.")
        if kind == "account_before_start":
            return (f"An attacker event of account {f.get('account')} at {f.get('time')} precedes the attacker's "
                    f"first use of that account: {where}. Say why the account was the attacker's then.")
        if kind == "label_conflict" and f.get("brief_label"):
            other = next((x for x in f.get("labels") or [] if x != f["brief_label"]), "")
            ekind = ""
            ref = str(f.get("ref") or "")
            if ref.startswith("e:") and ref[2:].isdigit():
                with self._read() as con:
                    row = con.execute("SELECT kind FROM entities WHERE eid = ?", (int(ref[2:]),)).fetchone()
                ekind = str(row["kind"]) if row else ""
            if f["brief_label"] != "benign":
                advice = "Record what the evidence shows of it; the disagreement stays stated in the report."
            elif ekind in ("host", "account"):
                # attacker_from exists for hosts and accounts: the window reads it.
                advice = ("An account or host the brief names as the organisation's that the attacker used is "
                          "labelled attacker with attacker_from at the attacker's first action with it: its earlier "
                          "activity stays the organisation's, and the brief's label stays beside it as the user's "
                          "statement. Record the attacker's actions with it as events.")
            else:
                advice = ("A file or address the brief names as the organisation's that the attacker used keeps the "
                          "evidence's label where the attacker used it (on that host, in that action), and the "
                          "brief's label stays beside it as the user's statement. Record the attacker's actions with "
                          "it as events.")
            return (f"The case brief, the user's own statement, calls {f.get('ref')} {f['brief_label']}, and a "
                    f"belief from the evidence labels it {other}. The brief is not evidence: never supersede a label "
                    "the evidence holds to agree with the brief. " + advice)
        if kind == "label_conflict":
            return (f"Current beliefs label {f.get('ref')} as {' and '.join(f.get('labels') or [])}; supersede the one "
                    "the evidence does not hold.")
        return ""

    def summary(self, focus: dict[str, Any] | None = None, budget_chars: int = 12000) -> str:
        """The map in plain lines for a prompt: the estate start; hosts by
        first attacker time with their start and how it is anchored;
        attacker entities by kind; the focus's labelled events; pending
        evidence near the focus. Fixed section order, rows by (time, id),
        cut at line ends to ``budget_chars`` with the count left out:
        deterministic for one state, so a prompt prefix stays cacheable."""
        self.sync()
        focus = focus or {}
        lines: list[str] = []
        with self._read() as con:
            w = self._window_core(con)
            firsts = self._meta(con, "host_first", {})
            inbound = self._inbound_hosts(con)
            lines.append(f"estate start: {w['estate'][0]} ({w['estate'][1]})" if w["estate"]
                         else "estate start: no anchor stated")
            for h in sorted(set(firsts) | set(w["hosts"]) | set(w["unanchored"]),
                            key=lambda h: ((firsts.get(h) or ["9"])[0], h)):
                own = w["hosts"].get(h)
                start = (f"start {own[0][0]} via {w['via'].get(h, 'row')} ({own[0][1]})" if own else
                         f"start from the estate start {w['estate'][0]}" if w["estate"] else "no anchor stated")
                first = f"first attacker event {firsts[h][0]} (v:{firsts[h][1]})" if h in firsts else "no attacker event"
                lines.append(f"host {h}: {first}; {start}; inbound edge: {'yes' if h in inbound else 'open'}")
            ents = []
            for eid in self._attacker_eids(con):
                e = con.execute("SELECT kind, display FROM entities WHERE eid = ?", (eid,)).fetchone()
                ents.append((e["kind"], e["display"].lower(), eid, e["display"]))
            for kind, _low, eid, disp in sorted(ents):
                lines.append(f"attacker {kind} e:{eid} {disp} (hosts: {', '.join(self._entity_hosts(con, eid)) or '-'})")
            fh = self.case_host(focus.get("host")) if focus.get("host") else ""
            feid = focus.get("entity_id")
            if fh or feid:
                sql = ("SELECT DISTINCT e.* FROM events e JOIN roles r ON r.vid = e.vid WHERE r.eid = ?" if feid
                       else "SELECT * FROM events e WHERE e.host = ?")
                for e in sorted(con.execute(sql, (int(feid) if feid else fh,)), key=lambda e: (e["t"], e["vid"])):
                    label, proposal = self._state(con, f"v:{e['vid']}")
                    if label:
                        aside = ("; not anchoring: its belief is about another host"
                                 if e["vid"] in w["not_anchoring"] else "")
                        lines.append(f"event v:{e['vid']} {e['t']} {e['host']} {e['kind']}"
                                     f"{' ' + e['verb'] if e['verb'] else ''}: {label}"
                                     f"{' (proposed)' if proposal else ''}{aside}")
            states = {k: (v[0] if isinstance(v, list) else v) for k, v in self._meta(con, "ledger_states", {}).items()}
            for r in con.execute("SELECT key, host, display FROM entities WHERE kind = 'evidence_item' ORDER BY key"):
                near = (not fh and not focus.get("item_id")) or r["host"] == fh or r["key"] == focus.get("item_id")
                if states.get(r["key"]) == "pending" and near:
                    lines.append(f"pending evidence {r['key']} on {r['host'] or '-'}: {r['display']}")
        out, size = [], 0
        for i, line in enumerate(lines):
            if size + len(line) + 1 > budget_chars - 40:
                out.append(f"({len(lines) - i} more lines)")
                break
            out.append(line)
            size += len(line) + 1
        return "\n".join(out)

    def _claim_hosts(self) -> list[tuple[str, str]]:
        with self._read() as con:
            return [(r[0], r[1]) for r in con.execute("SELECT claim_id, host FROM ingested")]

    def window(self, exclude: Iterable[str] = (), rows: Iterable[tuple] = ()) -> dict[str, Any]:
        """The incident window in the shape core.incident_window returns
        ({"hosts", "accounts", "estate", "attacker_accounts",
        "own_accounts", "compromised", "noted"}), anchored by the map's
        rule, plus "unanchored" (hosts with attacker labels and no start of
        their own, which take the estate start) and "via" (what anchors
        each host: inbound, event or row). ``exclude``: beliefs that do not
        count; ``rows``: (claim, type, value) rows whose anchors do not."""
        self.sync()
        graph_hosts = {str(c): h for c, h in self._claim_hosts()}
        skip = [(c, t, (self.case_host(v) or v) if t == "host"
                 else self.account_id(*self.account_identity(v, graph_hosts.get(str(c), ""))[:2]))
                for c, t, v in rows]
        exclude = {str(c) for c in exclude}
        with self._read() as con:
            w = self._window_core(con, exclude, skip)
            w.pop("_bounds")
            w.pop("not_anchoring")
            sides: dict[str, set[str]] = {}
            for r in con.execute(
                    "SELECT n.key, n.host, l.reason, l.claim_id FROM labels l JOIN entities n ON 'e:' || n.eid = l.target "
                    f"WHERE n.kind = 'account' AND l.by = 'ingest' AND l.proposal = 0 AND {_CURRENT}"):
                if r["claim_id"] not in exclude and str(r["reason"]).startswith("side:"):
                    sides.setdefault(self.account_id(r["key"], r["host"]), set()).add(r["reason"][5:])
        acted = set(w["accounts"])
        w["attacker_accounts"] = sorted(a for a, s in sides.items() if s == {"attacker"})
        w["own_accounts"] = sorted(a for a, s in sides.items()
                                   if "attacker" not in s and s & {"victim", "subject"} and a not in acted)
        from core.incident_window import split_own
        w.update(split_own(w["own_accounts"], sides))
        both = sorted(a for a, s in sides.items() if s & {"victim", "subject"} and ("attacker" in s or a in acted))
        w["compromised"] = {a: (w["accounts"].get(a) or [("", "")])[0][0] for a in both}
        return w

    def display(self, per_host: int = 300) -> dict[str, Any]:
        """The map as one reading: the estate start, the
        hosts in lane order (first attacker event first, unreached hosts
        after) with their start and how it is anchored, events per host
        (``per_host`` shown, the rest counted: a display bound, never a
        bound on what the map holds), labelled entities, declared views
        and the change counts. Reads only."""
        w = self.window()
        views = self.views()
        with self._read() as con:
            firsts = self._meta(con, "host_first", {}) or {}
            inbound = self._inbound_hosts(con)
            events_by: dict[str, list] = {}
            for e in con.execute("SELECT * FROM events ORDER BY t, vid").fetchall():
                label, proposal = self._state(con, f"v:{e['vid']}")
                claim = next((r["claim_id"] for r in reversed(self._current_labels(con, f"v:{e['vid']}"))
                              if r["claim_id"]), "")
                roles = {r: ", ".join(n["display"] for n in con.execute(
                    "SELECT n.display FROM roles x JOIN entities n ON n.eid = x.eid WHERE x.vid = ? AND x.role = ? "
                    "ORDER BY n.eid", (e["vid"], r))) for r in ("src", "dst", "actor")}
                events_by.setdefault(e["host"], []).append({
                    "vid": e["vid"], "host": e["host"], "t": e["t"], "kind": e["kind"], "verb": e["verb"],
                    "label": label or "", "proposal": bool(proposal), "claim": claim,
                    "coarse": e["kind"] == "other" and e["verb"] == "belief", **roles})
            entities = []
            for e in con.execute("SELECT * FROM entities WHERE kind NOT IN ('evidence_item', 'host') "
                                 "ORDER BY kind, display").fetchall():
                label, proposal = self._state(con, f"e:{e['eid']}")
                if label:
                    entities.append({"eid": e["eid"], "kind": e["kind"], "display": e["display"], "label": label,
                                     "proposal": bool(proposal), "hosts": self._entity_hosts(con, e["eid"])})
            counts = {r[0]: r[1] for r in con.execute("SELECT kind, COUNT(*) FROM changes GROUP BY kind")}
            joins: dict[str, int] = {}
            for (fields,) in con.execute("SELECT fields FROM changes WHERE kind = 'join_hit'"):
                h = json.loads(fields).get("host")
                joins[h] = joins.get(h, 0) + 1
        open_cells: dict[str, int] = {}
        for v in views:
            if v["declared_by"] == "default":
                continue
            for r in v["rows"]:
                open_cells[r["row_key"]] = open_cells.get(r["row_key"], 0) + sum(
                    1 for c in r["cells"].values() if c["open"])
        reached = set(firsts) | set(w["hosts"]) | set(w["unanchored"])
        hosts = []
        for h in sorted(set(self._hosts()) | reached | set(events_by),
                        key=lambda h: (h not in reached, (firsts.get(h) or ["~"])[0], h)):
            own = w["hosts"].get(h)
            start = ({"t": own[0][0], "claim": own[0][1], "via": w["via"].get(h, "row")} if own else
                     {"t": w["estate"][0], "claim": w["estate"][1], "via": "estate"}
                     if w["estate"] and h in w["unanchored"] else None)
            evs = events_by.get(h, [])
            hosts.append({"host": h, "reached": h in reached, "start": start,
                          "no_anchor": h in w["unanchored"], "first": firsts.get(h),
                          "inbound": h in inbound, "events": len(evs), "joins": joins.get(h, 0),
                          "open_cells": open_cells.get(h, 0)})
        return {"map": True,
                "estate_start": {"t": w["estate"][0], "claim": w["estate"][1]} if w["estate"] else None,
                "hosts": hosts,
                "events": [e for h in events_by for e in events_by[h][:per_host]],
                "more": {h: len(v) - per_host for h, v in events_by.items() if len(v) > per_host},
                "entities": entities,
                "views": [{"view_id": v["view_id"], "task": v["task_id"], "part": v["part_id"], "spec": v["spec"],
                           "rows": v["rows"], "open": sum(1 for r in v["rows"] if r["status"] == "open")}
                          for v in views if v["declared_by"] != "default"],
                "changes": counts}

    def brief_labels(self) -> dict[str, str]:
        """Target -> label of every current label the brief states."""
        self.sync()
        with self._read() as con:
            return {r[0]: r[1] for r in con.execute(
                f"SELECT l.target, l.label FROM labels l WHERE {_CURRENT} AND l.by = ? AND l.label != 'unknown'",
                (BRIEF,)).fetchall()}

    def observations(self) -> list[dict[str, Any]]:
        """Every observation the map keeps (facts with their basis that no
        finding states), oldest first: {text, host, time, call_ids, quotes}."""
        self.sync()
        with self._read() as con:
            rows = con.execute("SELECT host, attrs FROM entities WHERE kind = 'observation' ORDER BY eid").fetchall()
        out = []
        for r in rows:
            try:
                a = json.loads(r["attrs"] or "{}")
            except ValueError:
                a = {}
            out.append({"text": str(a.get("text") or ""), "host": r["host"] or "", "time": str(a.get("t") or ""),
                        "call_ids": list(a.get("call_ids") or []), "quotes": list(a.get("quotes") or [])})
        return out

    def counts(self) -> dict[str, int]:
        with self._read() as con:
            return {t: int(con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0])
                    for t in ("entities", "events", "labels", "sightings", "changes", "ingested")}
