"""Evidence items: every piece of evidence the case was handed, and
whether the run read it.

The coverage ledger's units are the finish floor (core.coverage_ledger).
An item is the reader's view beside them: each piece of evidence as it was
delivered. Every container under evidence/, at any depth, is an item of
its own: a disk or memory image with its segments, a capture, an archive.
The remaining files group by the top level of evidence/: a loose file, or
one tree per top-level folder, entered through folders that hold a single
entry. Items are grouped from the file list the unit walk reads (the
evidence profile), so a container is one for its unit and its item alike.
Items never hold the floor: they are disclosed in the report, carried into
a rerun and named before the finish.

Examined means contact, as for a unit: a successful call from a probe tool
named a path at or under one of the item's roots (its path and segments,
an image's mounts and raw exports, the folders an archive was extracted
to). A call naming only an ancestor of the item credits nothing, and a call
that records the model's own words credits nothing. For a tree or an
extracted archive the report says how many of its files and folders the
calls named, not what a recursive tool may have read.
"""
from __future__ import annotations

import datetime as _dt
import os
import re
from pathlib import Path
from typing import Any, Callable

from core.artifact_kind import is_ewf_continuation_segment

KINDS = ("image", "memory", "capture", "archive", "file", "tree")
_CLASS_KIND = {"disk": "image", "memory": "memory", "pcap": "capture"}
# What the archive tools open (tools/archives.py).
_ARCHIVE_SUFFIXES = (".zip", ".7z", ".rar", ".tar", ".tgz", ".tbz2", ".txz", ".gz", ".bz2", ".xz")
_SPLIT_RE = re.compile(r"\.(\d{3})$")
_VMDK_EXTENT_RE = re.compile(r"^(.+)-(?:flat|s\d{3}|f\d{3})\.vmdk$", re.I)
_STATE_KEYS = ("status", "touched", "calls", "examined_by", "examined_at", "blocked_reason")
# ponytail: a run naming more distinct paths under one item than this
# undercounts it; a set per item would lift it at the cost of ledger size.
MAX_TOUCHED = 2000
MAX_CALLS = 200
_ARCHIVE_SCAN_CAP = 20_000


def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _container_suffixes() -> tuple[str, ...]:
    from core.evidence_profile import _EXT_CLASS
    return tuple(e for e, c in _EXT_CLASS.items() if c in ("disk", "memory")) + _ARCHIVE_SUFFIXES


def _head(rel: str, present: set[str]) -> str:
    """The first segment a continuation segment is read through, "" for
    anything else. A numbered .002 folds into its .001 only when the stem
    names an image or an archive (or nothing), so rotated logs stay apart."""
    folder, _, name = rel.rpartition("/")
    cand = ""
    split = _SPLIT_RE.search(name)
    vmdk = _VMDK_EXTENT_RE.match(name)
    if is_ewf_continuation_segment(name):
        cand = name[:-2] + "01"
    elif split and int(split.group(1)) > 1:
        stem = name[:-4]
        if "." not in stem or stem.lower().endswith(_container_suffixes()):
            cand = stem + ".001"
    elif vmdk:
        cand = vmdk.group(1) + ".vmdk"
    if cand and folder:
        cand = f"{folder}/{cand}"
    return cand if cand in present else ""


def _kind(rel: str, cls: str, segmented: bool) -> str:
    """The container kind of a file, "" for a file that is not one."""
    if cls in _CLASS_KIND:
        return _CLASS_KIND[cls]
    low = rel.lower()
    base = low[:-4] if segmented and _SPLIT_RE.search(low) else low
    if base.endswith(_ARCHIVE_SUFFIXES):
        return "archive"
    return "image" if segmented else ""


def _split(files: list[dict[str, Any]]) -> tuple[dict[str, tuple[str, list[str]]], list[str]]:
    """Containers (head -> kind and segments) and the remaining files."""
    from core.coverage_ledger import is_noise_path
    cls: dict[str, str] = {}
    for f in files or []:
        if not isinstance(f, dict):
            continue
        rel = str(f.get("path") or "").replace("\\", "/").lstrip("./")
        if rel and "/" not in rel:
            rel = f"evidence/{rel}"
        if rel.startswith("evidence/") and not is_noise_path(rel):
            cls[rel] = str(f.get("class") or "")
    present = set(cls)
    segments: dict[str, list[str]] = {}
    heads: list[str] = []
    for rel in sorted(cls):
        head = _head(rel, present)
        if head:
            segments.setdefault(head, []).append(rel)
        else:
            heads.append(rel)
    containers: dict[str, tuple[str, list[str]]] = {}
    rest: list[str] = []
    for rel in heads:
        kind = _kind(rel, cls[rel], rel in segments)
        if kind:
            containers[rel] = (kind, segments.get(rel, []))
        else:
            rest.append(rel)
    return containers, rest


def _new(path: str, kind: str, segments: list[str] | None = None) -> dict[str, Any]:
    from core.coverage_ledger import _unit_id
    return {"id": _unit_id(path), "path": path, "kind": kind, "segments": list(segments or []),
            "status": "unseen", "touched": [], "calls": [], "examined_by": None,
            "examined_at": None, "blocked_reason": ""}


def build_items(files: list[dict[str, Any]], prev: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    """Items from the evidence profile's file list, keyed by id; the state
    of an item whose path is unchanged is carried over from ``prev``."""
    containers, rest = _split(files)
    found = [_new(rel, kind, segs) for rel, (kind, segs) in containers.items()]
    top: dict[str, Any] = {}
    for rel in rest:
        node = top
        parts = rel.split("/")[1:]
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = None
    for name, node in sorted(top.items()):
        path = f"evidence/{name}"
        while isinstance(node, dict) and len(node) == 1:
            (sub, node), = node.items()
            path = f"{path}/{sub}"
        found.append(_new(path, "file" if node is None else "tree"))
    items: dict[str, dict[str, Any]] = {}
    for item in found:
        old = (prev or {}).get(item["id"])
        if isinstance(old, dict) and old.get("path") == item["path"]:
            item.update({k: old[k] for k in _STATE_KEYS if k in old})
        items[item["id"]] = item
    return items


# ── contact ──────────────────────────────────────────────────────────────

def _extraction_dirs(ledger: dict[str, Any], item: dict[str, Any]) -> list[str]:
    """Case-relative folders the run extracted an archive item to."""
    own = {s.casefold() for s in [item["path"], *(item.get("segments") or [])]}
    return [str(u.get("path")) for u in (ledger.get("units") or {}).values()
            if isinstance(u, dict) and u.get("kind") == "derived"
            and str(u.get("source_rel") or "").casefold() in own]


def _roots(ledger: dict[str, Any]) -> list[tuple[str, str]]:
    """(casefolded root, item id), longest first, so a container inside a
    tree takes what lies under it."""
    out: list[tuple[str, str]] = []
    for iid, item in (ledger.get("items") or {}).items():
        if not isinstance(item, dict):
            continue
        roots = [item["path"], *(item.get("segments") or [])]
        if item.get("kind") == "archive":
            roots += _extraction_dirs(ledger, item)
        out += [(r.rstrip("/").casefold(), iid) for r in roots if r]
    return sorted(out, key=lambda r: -len(r[0]))


def observe(ledger: dict[str, Any], case_root: Path, paths: list[str], *,
            tool: str = "", call_id: str = "") -> bool:
    """Credit the items a successful probe call named. Returns whether
    anything changed; the caller saves the ledger."""
    items = ledger.get("items")
    if not isinstance(items, dict) or not items or _own_words(tool or ""):
        return False
    from core.coverage_ledger import _norm_rel, _source_images_for
    named = {_norm_rel(p).casefold() for p in paths if p} - {""}
    named |= _source_images_for(case_root, paths)
    roots = _roots(ledger)
    changed = False
    for n in sorted(named):
        for root, iid in roots:
            if n == root or n.startswith(root + "/"):
                changed |= _touch(items[iid], n, tool, call_id)
                break
    return changed


def _own_words(tool: str) -> bool:
    """A call whose arguments are the model's own words, by the registry the
    citation judge uses (core.forensic_citation): a finding or a coverage
    verdict that names a file is no read of it. A job start runs its tool
    over the evidence it names; the other job tools name only a job id."""
    if tool.startswith("job_"):
        return False
    from core.forensic_citation import own_words_entry
    return own_words_entry({"type": "tool_call", "cmd": f"<py>:{tool}"})


def _touch(item: dict[str, Any], path: str, tool: str, call_id: str) -> bool:
    changed = False
    touched = item.setdefault("touched", [])
    if path not in touched and len(touched) < MAX_TOUCHED:
        touched.append(path)
        changed = True
    calls = item.setdefault("calls", [])
    if call_id and call_id not in calls and len(calls) < MAX_CALLS:
        calls.append(call_id)
        changed = True
    if item.get("status") != "examined":
        item.update(status="examined", examined_at=_utcnow(), blocked_reason="",
                    examined_by={"call_id": call_id, "tool": tool})
        changed = True
    return changed


def reset(ledger: dict[str, Any]) -> int:
    """Every item back to unseen, for a cleared run. Returns how many changed."""
    n = 0
    for item in (ledger.get("items") or {}).values():
        if isinstance(item, dict) and (item.get("status") != "unseen" or item.get("touched")):
            item.update(status="unseen", touched=[], calls=[], examined_by=None,
                        examined_at=None, blocked_reason="")
            n += 1
    return n


def find(ledger: dict[str, Any], path: str) -> dict[str, Any] | None:
    from core.coverage_ledger import _norm_rel
    want = _norm_rel(path).rstrip("/").casefold()
    for item in (ledger.get("items") or {}).values():
        if isinstance(item, dict) and str(item.get("path") or "").casefold() == want:
            return item
    return None


# ── what the report, the rerun and the checks read ───────────────────────

def _ancestors(rel: str, root: str) -> list[str]:
    parts = rel.split("/")
    depth = root.count("/") + 1
    return ["/".join(parts[:i]) for i in range(depth, len(parts))]


def _files_under(case_root: Path, rel_dir: str) -> list[str]:
    out: list[str] = []
    for dirpath, _dirs, names in os.walk(case_root / rel_dir):
        for name in names:
            out.append(os.path.relpath(os.path.join(dirpath, name), case_root).replace(os.sep, "/"))
            if len(out) >= _ARCHIVE_SCAN_CAP:
                return out
    return out


def rows(case_dir: str | os.PathLike, ledger: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Every item with, for a tree or an extracted archive, the number of
    files it holds and how many of its files and folders the calls named."""
    from core.coverage_ledger import load_ledger
    case_root = Path(case_dir).resolve()
    ledger = ledger if ledger is not None else load_ledger(case_root)
    items = ledger.get("items")
    if not isinstance(items, dict) or not items:
        return []
    rest: list[str] | None = None
    out: list[dict[str, Any]] = []
    for item in sorted((i for i in items.values() if isinstance(i, dict)), key=lambda i: i["path"]):
        row = dict(item)
        files: list[str] = []
        roots: list[str] = []
        if item.get("kind") == "tree":
            if rest is None:
                try:
                    from core.evidence_profile import ensure_evidence_profile
                    rest = _split(ensure_evidence_profile(str(case_root)).get("files") or [])[1]
                except Exception:  # noqa: BLE001 - no profile, no counts
                    rest = []
            prefix = item["path"].casefold() + "/"
            files = [r.casefold() for r in rest if r.casefold().startswith(prefix)]
            roots = [item["path"].casefold()]
        elif item.get("kind") == "archive":
            for d in _extraction_dirs(ledger, item):
                files += [f.casefold() for f in _files_under(case_root, d)]
                roots.append(d.rstrip("/").casefold())
        if files:
            touched = set(item.get("touched") or [])
            folders = {a for f in files for r in roots if f.startswith(r + "/") for a in _ancestors(f, r)}
            folders |= set(roots)
            row.update(files=len(files), named_files=len(touched & set(files)),
                       named_folders=len(touched & folders))
        out.append(row)
    return out


def withheld_test(case_dir: str | os.PathLike) -> Callable[[dict[str, Any]], bool]:
    """Which items the report lists without a name under a standing
    handling stop: a media file, and anything on a device handed over."""
    case_root = Path(case_dir).resolve()
    try:
        from core import handling_stop as hs
        st = hs.state(case_root)
    except Exception:  # noqa: BLE001
        st = None
    if not st:
        return lambda item: False
    roots = hs.device_paths(case_root, st.get("device") or "") if st.get("frame") == "incident" else []

    def test(item: dict[str, Any]) -> bool:
        p = case_root / str(item.get("path") or "")
        if roots and hs._under(str(p), roots):
            return True
        return item.get("kind") != "tree" and hs.path_is_media(p)
    return test


def counts(item_rows: list[dict[str, Any]]) -> dict[str, int]:
    c = {"total": len(item_rows), "examined": 0, "blocked": 0, "unseen": 0}
    for r in item_rows:
        st = r.get("status") if r.get("status") in ("examined", "blocked") else "unseen"
        c[st] += 1
    return c


def unseen(case_dir: str | os.PathLike | None, *, limit: int = 40) -> list[str]:
    """Paths of the items no call has read, blocked ones and ones handed
    over under a handling stop left out: what a rerun still has to do."""
    if not case_dir:
        return []
    try:
        from core.coverage_ledger import load_ledger
        items = load_ledger(case_dir).get("items") or {}
        withheld = withheld_test(case_dir)
    except Exception:  # noqa: BLE001
        return []
    out = [str(i["path"]) for i in sorted((i for i in items.values() if isinstance(i, dict)),
                                          key=lambda i: i["path"])
           if i.get("status") == "unseen" and not withheld(i)]
    return out[:limit]


_T = {
    "en": {
        "title": "Evidence coverage",
        "summary": "{examined} of {total} delivered items examined, {blocked} blocked, {unseen} not examined.",
        "legend": ("Examined means a tool call read the item (contact, not full analysis): for an image, "
                   "its content was reached through a mount, an export or a read. For a folder or an "
                   "extracted archive the status says how many of its files and folders the calls named."),
        "head": "| Item | Kind | Status | Examined by | Findings |",
        "unseen": "not examined", "examined": "examined", "blocked": "blocked",
        "named": "examined: named {n} of {m} files", "folders": " and {k} folders",
        "segments": " (+{n} segments)", "withheld": "withheld under the handling stop",
        "call": "call {id}",
        "gap_unseen": "- Not examined: {name} ({kind}); no content of it was read.",
        "gap_blocked": "- Blocked: {name} ({kind}): {reason}",
        "image": "image", "memory": "memory", "capture": "capture", "archive": "archive",
        "file": "file", "tree": "folder",
    },
    "de": {
        "title": "Auswertung der Beweismittel",
        "summary": "{examined} von {total} gelieferten Beweismitteln ausgewertet, {blocked} blockiert, {unseen} nicht ausgewertet.",
        "legend": ("Ausgewertet heißt, ein Werkzeugaufruf hat das Beweismittel gelesen (Kontakt, keine vollständige "
                   "Analyse): bei einem Abbild wurde sein Inhalt über eine Einbindung, einen Export oder einen "
                   "Lesezugriff erreicht. Bei einem Ordner oder einem entpackten Archiv nennt der Status, wie viele "
                   "seiner Dateien und Ordner die Aufrufe benannt haben."),
        "head": "| Beweismittel | Art | Status | Ausgewertet durch | Erkenntnisse |",
        "unseen": "nicht ausgewertet", "examined": "ausgewertet", "blocked": "blockiert",
        "named": "ausgewertet: {n} von {m} Dateien benannt", "folders": " und {k} Ordner",
        "segments": " (+{n} Segmente)", "withheld": "zurückgehalten wegen des Umgangsstopps",
        "call": "Aufruf {id}",
        "gap_unseen": "- Nicht ausgewertet: {name} ({kind}); kein Inhalt davon wurde gelesen.",
        "gap_blocked": "- Blockiert: {name} ({kind}): {reason}",
        "image": "Abbild", "memory": "Arbeitsspeicher", "capture": "Mitschnitt", "archive": "Archiv",
        "file": "Datei", "tree": "Ordner",
    },
}


def _tx(language: str) -> dict[str, str]:
    return _T["de" if language == "de" else "en"]


def _name(row: dict[str, Any], withheld: bool, tx: dict[str, str]) -> str:
    if withheld:
        return tx["withheld"]
    segs = row.get("segments") or []
    return f"`{row['path']}`" + (tx["segments"].format(n=len(segs)) if segs else "")


def _status(row: dict[str, Any], tx: dict[str, str]) -> str:
    st = row.get("status")
    if st == "blocked":
        return tx["blocked"] + (f": {str(row.get('blocked_reason') or '')[:160]}" if row.get("blocked_reason") else "")
    if st != "examined":
        return tx["unseen"]
    if row.get("files"):
        return (tx["named"].format(n=row.get("named_files", 0), m=row["files"])
                + (tx["folders"].format(k=row["named_folders"]) if row.get("named_folders") else ""))
    return tx["examined"]


def _finding_ids(row: dict[str, Any], findings: list[dict[str, Any]]) -> list[str]:
    calls = {str(c) for c in row.get("calls") or []}
    out: list[str] = []
    for f in findings or []:
        cited = {str(c) for c in (f.get("input_call_ids") or [])}
        cited |= {str(e.get("call_id")) for e in (f.get("evidence") or []) if isinstance(e, dict)}
        fid = str(f.get("finding_id") or f.get("id") or "")
        if fid and calls & cited and fid not in out:
            out.append(fid)
    return out


def report_lines(case_dir: str | os.PathLike, findings: list[dict[str, Any]] | None = None,
                 language: str = "en") -> list[str]:
    """The Scope and Evidence block: one line of counts, the legend, and a
    row per item, the ones not examined first."""
    item_rows = rows(case_dir)
    if not item_rows:
        return []
    tx = _tx(language)
    withheld = withheld_test(case_dir)
    lines = [f"**{tx['title']}:** " + tx["summary"].format(**counts(item_rows)), "", tx["legend"], "",
             tx["head"], "|---|---|---|---|---|"]
    order = {"unseen": 0, "blocked": 1, "examined": 2}
    for row in sorted(item_rows, key=lambda r: (order.get(r.get("status"), 0), r["path"])):
        by = row.get("examined_by") or {}
        who = (tx["call"].format(id=by["call_id"]) + f" ({by.get('tool')})") if by.get("call_id") else (by.get("tool") or "—")
        fids = _finding_ids(row, findings or [])
        lines.append(f"| {_name(row, withheld(row), tx)} | {tx.get(row.get('kind'), row.get('kind'))} | "
                     f"{_status(row, tx)} | {who} | {', '.join(fids) or '—'} |")
    return lines


def gap_lines(case_dir: str | os.PathLike, language: str = "en") -> list[str]:
    """Evidence Gaps: every item not examined, and every blocked one with
    its reason."""
    item_rows = rows(case_dir)
    tx = _tx(language)
    withheld = withheld_test(case_dir)
    out: list[str] = []
    for row in item_rows:
        kind = tx.get(row.get("kind"), row.get("kind"))
        if row.get("status") == "blocked":
            out.append(tx["gap_blocked"].format(name=_name(row, withheld(row), tx), kind=kind,
                                                reason=str(row.get("blocked_reason") or "")[:200]))
        elif row.get("status") != "examined":
            out.append(tx["gap_unseen"].format(name=_name(row, withheld(row), tx), kind=kind))
    return out
