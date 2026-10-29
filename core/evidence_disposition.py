"""Evidence disposition (ATLAS_EVIDENCE_DISPOSITION): every handed-over
evidence item and every content class inside it is triaged, never left
untouched without a checked reason.

Three levels in the coverage ledger, no new store:
- item: each piece of evidence the case was handed (ledger["items"],
  core.evidence_items);
- class: the content classes inside an item (ledger["classes"]): for a
  disk image the classes the contents index gives its entries (the
  artefact-value table's identity labels, core.artifact_value) and the
  profile's format classes; for a collected tree the same labels over its
  files. Format knowledge, never a map from a question to an artefact;
- artefact: the ledger's high-value units (ledger["units"]).

Each item and class carries a disposition: state (pending, relevant, read,
partial, left), reason_kind, reason, proof_call_ids, scope_fingerprint and
acknowledged_entities. A surveyed but pending unit is never counted as
touched. A unit the model marked blocked in its own words migrates to
pending with that reason attached, so it is triaged again under the leave
checks.
"""
from __future__ import annotations

from core.store_lock import locked as _locked

import os
from pathlib import Path
import re
from typing import Any

STATES = ("pending", "relevant", "parsed", "read", "partial", "walked", "swept", "left")

# The structures a memory image holds, and the plugin names that read each
# (Volatility's public plugin vocabulary): capability, like the readers by
# format, so a memory item's classes are credited when such a plugin ran on
# it. Never a choice of what to look for.
MEMORY_STRUCTURES = {
    "processes": ("pslist", "pstree", "psscan", "psxview"),
    "network endpoints": ("netscan", "netstat", "sockscan", "sockets"),
    "loaded modules": ("dlllist", "ldrmodules", "modules", "modscan"),
    "command lines": ("cmdline", "consoles", "cmdscan"),
    "registry in memory": ("hivelist", "hivescan", "printkey", "userassist", "registry"),
    "file objects": ("filescan", "dumpfiles", "handles"),
}
NO_CLASSES_NOTE = "no content classes known"
# How a memory plugin reads its structure, in Volatility's public vocabulary
# of the mechanism: a scan reads the whole image for the structure's pool
# tags and also finds unlinked and freed objects; a walk follows the
# kernel's lists from their heads (fast on a cold image, but it misses
# what was unlinked). Capability, never a choice of what to look for.
# psxview cross-views the process walk against the pool and thread scans, so
# it reads (and costs) a scan.
SCAN_PLUGINS = frozenset({"psscan", "psxview", "netscan", "sockscan", "modscan", "cmdscan", "hivescan",
                          "filescan", "malfind", "vadyarascan", "yarascan", "driverscan", "mutantscan", "svcscan"})


def memory_cost(plugin: str) -> str:
    """"scan" or "walk" for a memory plugin name (its last name part)."""
    name = re.split(r"[._]", str(plugin or "").lower())[-1]
    return "scan" if name in SCAN_PLUGINS else "walk"


def writes_files(plugin: str) -> bool:
    """A plugin whose answer is the files it writes (an extraction, never a
    walk of the structure's lists; core.vol_cache's public vocabulary)."""
    from core.vol_cache import writes_files as _writes
    return _writes(str(plugin or ""), None)


def walk_first(plugins) -> list[str]:
    """A structure's plugins with its walks before its scans and the file
    writers last, each group in its declared order. A writer still credits
    the structure when it ran; it is never the walk offered or planned."""
    return sorted(plugins, key=lambda p: 2 if writes_files(p) else int(memory_cost(p) == "scan"))


def first_walk(plugins) -> str:
    """The structure's walk to run or offer first ("" when none)."""
    return next((p for p in walk_first(plugins) if memory_cost(p) == "walk" and not writes_files(p)), "")
LEVELS = ("item", "class", "artefact")
_EMPTY_MARK = " (appears empty)"


def disposition_on() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_EVIDENCE_DISPOSITION", True)


def _fresh() -> dict[str, Any]:
    return {"state": "pending", "reason_kind": "", "reason": "", "proof_call_ids": [],
            "scope_fingerprint": "", "acknowledged_entities": [], "reopened": 0}


_FIELDS = tuple(_fresh())


def _carry(new: dict[str, Any], old: dict[str, Any] | None) -> None:
    """The disposition of a unit seen before stands across a rebuild."""
    base = _fresh()
    for k in _FIELDS:
        new[k] = old[k] if isinstance(old, dict) and k in old else base[k]


def _host(case_dir: Path, path: str) -> str:
    try:
        from core.evidence_links import host_of_path
        return host_of_path(case_dir, path)
    except Exception:  # noqa: BLE001
        return ""


def _label(raw: str) -> tuple[str, bool]:
    raw = str(raw or "")
    return (raw[:-len(_EMPTY_MARK)], True) if raw.endswith(_EMPTY_MARK) else (raw, False)


def _image_classes(case_dir: Path, item: dict[str, Any]) -> dict[str, dict[str, int]]:
    """{label: {"files", "empty"}} of an image item's live entries by the
    index's class column, plus the profile's format classes by suffix."""
    from contextlib import closing
    try:
        from core.contents_index import _connect, _rel
        con = _connect(case_dir)
    except Exception:  # noqa: BLE001
        return {}
    if con is None:
        return {}
    out: dict[str, dict[str, int]] = {}
    with closing(con):
        img = item["path"]
        for raw, n, score in con.execute(
                "SELECT class, COUNT(*), MAX(score) FROM entries WHERE origin = 'image' AND image = ? AND is_dir = 0 "
                "AND deleted = 0 AND version_of IS NULL AND class IS NOT NULL AND class != '' GROUP BY class",
                (img,)):
            label, empty = _label(raw)
            acc = out.setdefault(label, {"files": 0, "empty": 0, "score": 0})
            acc["files"] += int(n)
            acc["empty"] += int(n) if empty else 0
            acc["score"] = max(acc["score"], int(score or 0))
        for label, n in _suffix_classes(con, "image = ?", [img]).items():
            out.setdefault(label, {"files": n, "empty": 0, "score": 0})
        # A few member names per class (the first by score), so a reader
        # can be named for the class without a query per turn.
        for raw, name in con.execute(
                "SELECT class, name FROM entries WHERE origin = 'image' AND image = ? AND is_dir = 0 "
                "AND deleted = 0 AND version_of IS NULL AND class IS NOT NULL AND class != '' "
                "ORDER BY score DESC LIMIT 4000", (img,)):
            label, _empty = _label(raw)
            acc = out.get(label)
            if acc is None:
                continue
            names = acc.setdefault("names", [])
            low = str(name or "").rsplit("/", 1)[-1].lower()
            if low and low not in names and len(names) < 5:
                names.append(low)
    return out


def suffix_classes() -> dict[str, list[str]]:
    """{label: [suffixes]} of the format classes an image's entries are also
    counted in by name (the ones the class column does not carry): the one
    member rule of _image_classes and of the read credit
    (core.contents_index.read_state_by_class)."""
    from core.evidence_profile import _EXT_CLASS, _INSIDE_IMAGE_CLASSES
    by: dict[str, list[str]] = {}
    for suf, cls in _EXT_CLASS.items():
        # Event logs carry the index's own labels (a channel each); mail
        # stores and captures have none, so their format class stands.
        if cls in _INSIDE_IMAGE_CLASSES and cls != "windows_eventlog":
            by.setdefault(cls.replace("_", " "), []).append(suf)
    return by


def _suffix_classes(con, where: str, args: list) -> dict[str, int]:
    out: dict[str, int] = {}
    for label, sufs in suffix_classes().items():
        like = " OR ".join("lower(name) LIKE ?" for _ in sufs)
        n = con.execute(f"SELECT COUNT(*) FROM entries WHERE origin = 'image' AND is_dir = 0 AND deleted = 0 "
                        f"AND version_of IS NULL AND {where} AND ({like})",
                        [*args, *[f"%{s}" for s in sufs]]).fetchone()[0]
        if n:
            out[label] = int(n)
    return out


def _tree_classes(case_dir: Path, item: dict[str, Any], files: list[dict]) -> dict[str, dict[str, int]]:
    """The same labels over the files of a collected tree or a loose file."""
    from core.artifact_value import artifact_score
    return {label: {"files": len(m), "empty": sum(e for _r, e in m),
                    "score": max((artifact_score(rel)[0] for rel, _e in m), default=0)}
            for label, m in _tree_members(item, files).items()}


def _tree_members(item: dict[str, Any], files: list[dict]) -> dict[str, list[tuple[str, bool]]]:
    """Per label, the (case path, appears empty) of each file of a collected
    tree or a loose file, from the evidence profile's files: the one member
    set the classes are built from (_tree_classes) and credited by
    (credit_dispositions)."""
    from core.artifact_value import artifact_score
    root = item["path"].rstrip("/") + "/"
    out: dict[str, list[tuple[str, bool]]] = {}
    for f in files:
        rel = str(f.get("path") or "")
        if not (rel == item["path"] or rel.startswith(root)):
            continue
        _score, raw = artifact_score(rel, f.get("size"))
        if not raw:
            continue
        label, empty = _label(raw)
        out.setdefault(label, []).append((rel, bool(empty)))
    return out


def reopen(unit: dict[str, Any], reason: str) -> None:
    """Put a unit back to pending (in place), its leave kind cleared (a
    pending unit carries no leave), and count the reopen, so a reader that
    compares states between two saves still sees each one."""
    unit.update(state="pending", reason=str(reason)[:500], reason_kind="",
                reopened=int(unit.get("reopened") or 0) + 1)
    unit.pop("no_reader_key", None)          # checked again by the next code pass


def class_id(item_id: str, label: str) -> str:
    import hashlib
    return f"{item_id}#{hashlib.sha1(label.encode('utf-8')).hexdigest()[:10]}"


def build_disposition(case_dir: str | os.PathLike, ledger: dict[str, Any], prev: dict[str, Any] | None,
                      files: list[dict] | None = None) -> None:
    """Add the item and class levels to a ledger being built (in place):
    items gain host, level and their disposition; ledger["classes"] holds
    each item's content classes; units gain level "artefact". A unit or an
    item the model marked blocked migrates to pending with its reason."""
    root = Path(case_dir).resolve()
    prev = prev or {}
    prev_items = prev.get("items") or {}
    prev_classes = prev.get("classes") or {}
    for u in (ledger.get("units") or {}).values():
        if not isinstance(u, dict):
            continue
        u["level"] = "artefact"
        old = (prev.get("units") or {}).get(u.get("id")) or {}
        _carry(u, old if "state" in old else (u if "state" in u else None))
        if u.get("status") == "blocked" and not old.get("state"):
            # The model's own word settles nothing: the floor sees it unseen
            # again until a read or a checked leave settles it.
            u.update(state="pending", reason=str(u.get("note") or ""), migrated_from="blocked", status="unseen")
    classes: dict[str, dict[str, Any]] = {}
    for iid, item in (ledger.get("items") or {}).items():
        if not isinstance(item, dict):
            continue
        old = prev_items.get(iid) if isinstance(prev_items.get(iid), dict) else {}
        item["level"] = "item"
        item["host"] = item.get("host") or _host(root, item["path"])
        _carry(item, old if "state" in old else (item if "state" in item else None))
        if item.get("status") == "blocked" and not old.get("state"):
            item.update(state="pending", reason=str(item.get("blocked_reason") or ""), migrated_from="blocked",
                        status="unseen")
        if item.get("kind") == "image":
            found = _image_classes(root, item)
        elif item.get("kind") in ("tree", "file"):
            found = _tree_classes(root, item, files or [])
        elif item.get("kind") == "memory":
            found = {label: {"files": 0, "empty": 0, "score": 0} for label in MEMORY_STRUCTURES}
        else:
            found = {}
        for label, n in sorted(found.items()):
            cid = class_id(iid, label)
            unit = {"id": cid, "level": "class", "item": iid, "host": item["host"], "label": label,
                    "files": n["files"], "empty": n["empty"], "score": int(n.get("score") or 0),
                    "names": list(n.get("names") or [])[:5]}
            _carry(unit, prev_classes.get(cid))
            if unit["state"] == "pending" and n["files"] and n["empty"] == n["files"]:
                # A code fact with its own kind: every file of the class
                # appears empty (checked against the index like any leave,
                # recomputed at every build, never re-judged as a model's).
                unit.update(state="left", reason_kind="empty", reason="by code: all its files appear empty",
                            scope_fingerprint=_fingerprint(root))
            elif unit["state"] == "left" and unit.get("reason_kind") == "empty" and n["empty"] != n["files"]:
                # The fact no longer holds (a file of the class has content now).
                reopen(unit, "a file of this class no longer appears empty")
            classes[cid] = unit
    ledger["classes"] = classes


def _fingerprint(root) -> str:
    try:
        from core.evidence_leave import scope_fingerprint
        return scope_fingerprint(root)
    except Exception:  # noqa: BLE001
        return ""


def undecided_classes(ledger: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The classes with neither a read credited nor a reason: pending or
    relevant, whatever the model said in words. The one list the finish,
    the Report push, the report and the Coverage tab read."""
    return [c for c in ((ledger or {}).get("classes") or {}).values()
            if isinstance(c, dict) and c.get("state") in ("pending", "relevant")]


def undecided_items(ledger: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The items the ledger holds no class for that are still to be read
    (pending or relevant): they stand as one cheap class each
    (core.evidence_depth.depth_by_host), so they are undecided like a
    class, and a run that leaves one ends stopped, never finished."""
    classes = (ledger or {}).get("classes") or {}
    with_classes = {str(c.get("item") or "") for c in classes.values() if isinstance(c, dict)}
    return [i for iid, i in ((ledger or {}).get("items") or {}).items()
            if isinstance(i, dict) and str(iid) not in with_classes and i.get("state") in ("pending", "relevant")]


def undecided_by_host(ledger: dict[str, Any] | None) -> dict[str, int]:
    """{host or item name: undecided classes, a classless undecided item
    counting as one} (core.evidence_depth.item_labels: an item with no
    host is named by its file)."""
    from core.evidence_depth import item_labels, unit_host
    items = (ledger or {}).get("items") or {}
    labels = item_labels(items)
    out: dict[str, int] = {}
    for c in undecided_classes(ledger):
        h = labels.get(str(c.get("item") or ""), unit_host(c, items))
        out[h] = out.get(h, 0) + 1
    for i in undecided_items(ledger):
        h = labels.get(str(i.get("id") or ""), unit_host(i, items))
        out[h] = out.get(h, 0) + 1
    return out


def disposition_stats(ledger: dict[str, Any] | None) -> dict[str, dict[str, int]]:
    """{level: {state: n}} over the items, classes and artefact units."""
    ledger = ledger or {}
    out: dict[str, dict[str, int]] = {}
    for level, units in (("item", ledger.get("items")), ("class", ledger.get("classes")),
                         ("artefact", ledger.get("units"))):
        counts = {s: 0 for s in STATES}
        for u in (units or {}).values():
            if isinstance(u, dict):
                st = str(u.get("state") or "pending")
                counts[st if st in counts else "pending"] += 1
        out[level] = counts
    return out


def walked_only(ledger: dict[str, Any]) -> list[str]:
    """"<item>: <class>" of every memory class only walked: its scan did not
    run, so unlinked and freed objects are not seen. Disclosed, never
    blocking."""
    items = ledger.get("items") or {}
    return sorted(f"{(items.get(c.get('item')) or {}).get('path') or c.get('item')}: {c.get('label')}"
                  for c in (ledger.get("classes") or {}).values()
                  if isinstance(c, dict) and c.get("state") == "walked")


def disposition_complete(case_dir: str | os.PathLike) -> tuple[bool, dict[str, Any]]:
    """Whether the evidence disposition lets a run be complete: no pending
    item or class, and every left unit's check holding under the final
    scope (a unit whose scope changed is checked again, read-only).
    (ok, {"pending_items", "pending_classes", "left_not_holding"})."""
    from core.coverage_ledger import load_ledger
    ledger = load_ledger(case_dir)
    if ledger.get("classes") is None:
        return True, {}
    from core.evidence_leave import check_leave, scope_fingerprint
    stats = disposition_stats(ledger)
    current = scope_fingerprint(case_dir)
    not_holding: list[str] = []
    from core.evidence_leave import CODE_KINDS
    for level, units in (("item", ledger.get("items") or {}), ("class", ledger.get("classes") or {})):
        for unit in units.values():
            if not isinstance(unit, dict) or unit.get("state") != "left" or unit.get("scope_fingerprint") == current:
                continue
            if level == "class" and str(unit.get("reason") or "").startswith("with its item:"):
                continue
            if unit.get("reason_kind") in CODE_KINDS or str(unit.get("reason") or "").startswith("by code:"):
                # A code fact is recomputed by the pass that made it, never
                # re-judged as a model's leave.
                continue
            ref = unit["id"] if level == "class" else unit["path"]
            verdict = check_leave(case_dir, ledger, ref, str(unit.get("reason_kind") or ""),
                                  str(unit.get("reason") or "kept"), list(unit.get("proof_call_ids") or []),
                                  ignore_entities=frozenset(unit.get("acknowledged_entities") or []))
            if not verdict["ok"]:
                not_holding.append(ref)
    undecided = undecided_classes(ledger)
    und_items = undecided_items(ledger)         # a classless item still to be read counts as one
    detail = {"pending_items": stats["item"]["pending"], "pending_classes": stats["class"]["pending"],
              "relevant_not_read": _relevant_not_read(ledger), "left_not_holding": not_holding,
              "walked_only": walked_only(ledger), "undecided_classes": len(undecided) + len(und_items),
              "undecided_items": len(und_items), "undecided_by_host": undecided_by_host(ledger),
              "undecided_ids": ([c["id"] for c in undecided] + [str(i.get("id") or "") for i in und_items])[:200]}
    return (detail["pending_items"] == 0 and detail["pending_classes"] == 0 and not detail["relevant_not_read"]
            and not not_holding), detail


def _relevant_not_read(ledger: dict[str, Any]) -> int:
    """Units marked to be read that no read has credited: every class, and
    every item without classes (an item with classes follows them)."""
    classes = [c for c in (ledger.get("classes") or {}).values() if isinstance(c, dict)]
    with_classes = {c.get("item") for c in classes}
    # parsed is open: a parser wrote the class's rows and nobody looked at
    # them; it has a next step (query the output), never a reason.
    n = sum(1 for c in classes if c.get("state") in ("relevant", "parsed"))
    n += sum(1 for iid, i in (ledger.get("items") or {}).items()
             if isinstance(i, dict) and iid not in with_classes and i.get("state") == "relevant")
    return n


def kind_text(kind: Any, language: str = "en") -> str:
    """A leave kind as the report says it; a code fact (no kind) as such."""
    from core.report_i18n import t
    return t(f"ed_kind_{kind}" if kind else "ed_kind_code", language)


def report_lines(case_dir: str | os.PathLike, language: str = "en", host: str = "") -> list[str]:
    """The report's "Evidence not analysed": every left item or class with
    its kind, reason and proof; the partial ones with what was read; the
    units still pending. A class left with its item is counted on the
    item's line. ``host``: a host report's own items only."""
    from core.coverage_ledger import load_ledger
    from core.report_i18n import t
    ledger = load_ledger(case_dir)
    if ledger.get("classes") is None:
        return []
    items = ledger.get("items") or {}
    classes = ledger.get("classes") or {}
    mine = {iid for iid, i in items.items() if isinstance(i, dict)
            and (not host or str(i.get("host") or "").casefold() == host.casefold())}
    lines: list[str] = []

    def proof(u: dict) -> str:
        ids = [str(p) for p in u.get("proof_call_ids") or [] if p]
        return f" ({t('ed_proof', language)}: {', '.join(ids[:6])})" if ids else ""
    parsed: dict[str, list[str]] = {}
    filters: dict[str, set[str]] = {}
    none_kept: dict[str, list[str]] = {}
    overwritten: dict[str, list[str]] = {}
    undecided_lines: list[str] = []
    for iid in sorted(mine, key=lambda i: items[i]["path"]):
        item = items[iid]
        own = [c for c in classes.values() if isinstance(c, dict) and c.get("item") == iid]
        for c in own:
            if c.get("state") == "parsed" and c.get("overwritten"):
                overwritten.setdefault(c["overwritten"][0], []).append(
                    f"{item.get('host') or item['path']}: {c['label']}")
            elif c.get("state") == "parsed" and c.get("no_rows"):
                none_kept.setdefault("; ".join(c.get("parse_filters") or []) or "the parse", []).append(
                    f"{item.get('host') or item['path']}: {c['label']}")
            elif c.get("state") == "parsed" and c.get("outputs"):
                # One line per output file: its classes nobody looked at.
                where = (c.get("outputs") or ["?"])[0]
                parsed.setdefault(where, []).append(f"{item.get('host') or item['path']}: {c['label']}")
                filters.setdefault(where, set()).update(c.get("parse_filters") or [])
        if item.get("state") == "left":
            n = sum(1 for c in own if str(c.get("reason") or "").startswith("with its item:"))
            lines.append(f"- {item['path']}{' (' + item['host'] + ')' if item.get('host') else ''}: "
                         f"{t('ed_left', language)}, {kind_text(item.get('reason_kind'), language)}: "
                         f"{item.get('reason')}{proof(item)}"
                         + (f" ({t('ed_with_classes', language).format(n=n)})" if n else ""))
            continue
        for c in sorted(own, key=lambda c: c["label"]):
            if c.get("state") == "left":
                # A code fact's kind says it all; its stored reason repeats it.
                why = "" if str(c.get("reason") or "").startswith("by code:") else f": {c.get('reason')}"
                lines.append(f"- {item['path']}: {c['label']} ({c['files']}): {t('ed_left', language)}, "
                             f"{kind_text(c.get('reason_kind'), language)}{why}{proof(c)}")
            elif c.get("state") == "partial":
                # What the index credits, never the triage's words.
                lines.append(f"- {item['path']}: {c['label']} ({c['files']}): {t('ed_partial', language)}: "
                             f"{c.get('credited') or c.get('reason')}")
            elif c.get("state") in ("relevant", "pending") and not c.get("triage_refused"):
                undecided_lines.append(f"- {item.get('host') or item['path']}: {c['label']} ({c['files']})")
            elif c.get("state") == "walked":
                lines.append(f"- {item['path']}: {c['label']}: {t('ed_walked', language)}")
            elif c.get("state") == "parsed" and not (c.get("outputs") or c.get("no_rows") or c.get("overwritten")):
                # Parsed into no output file: no output line can name it.
                lines.append(f"- {item['path']}: {c['label']} ({c['files']}): {c.get('reason')}")
            elif c.get("state") == "swept":
                lines.append(f"- {item['path']}: {c['label']} ({c['files']}): {c.get('reason')}")
            elif c.get("state") == "pending" and c.get("triage_refused"):
                lines.append(f"- {item['path']}: {c['label']} ({c['files']}): "
                             + t("ed_refused", language).format(why=c["triage_refused"]))
    from core.evidence_depth import unit_host
    for iid in sorted(mine, key=lambda i: items[i]["path"]):
        item = items[iid]
        # An item with no class units: still to be read, it is undecided
        # like a class (it stands as one cheap class) and is listed under
        # the "Evidence not decided" heading; partly read, it is named
        # here; a read, walked or swept one is analysed, and a note about
        # it under "not analysed" would contradict its own state.
        if any(isinstance(c, dict) and c.get("item") == iid for c in classes.values()):
            continue
        if item.get("state") in ("pending", "relevant"):
            undecided_lines.append(f"- {unit_host(item, items)}: {item['path']} ({t('ed_no_classes', language)})")
        elif item.get("state") == "partial":
            lines.append(f"- {item['path']}: {t('ed_no_classes', language)} ({item.get('state')})")
    for where, labels in sorted(parsed.items()):
        f = sorted(filters.get(where) or [])
        lines.append(f"- {where}: " + t("ed_parsed", language).format(
            n=len(labels), labels=", ".join(labels[:8]) + (f", +{len(labels) - 8}" if len(labels) > 8 else ""),
            filters=f" (parsed with {'; '.join(f[:2])} only)" if f else ""))
    for where, labels in sorted(overwritten.items()):
        lines.append(f"- {where}: " + t("ed_overwritten", language).format(
            n=len(labels), labels=", ".join(labels[:8]) + (f", +{len(labels) - 8}" if len(labels) > 8 else "")))
    for flt, labels in sorted(none_kept.items()):
        lines.append("- " + t("ed_no_rows", language).format(
            filter=flt, n=len(labels), labels=", ".join(labels[:8]) + (f", +{len(labels) - 8}" if len(labels) > 8 else "")))
    pending = [u for u in (items[i] for i in mine) if u.get("state") == "pending"
               and not any(isinstance(c, dict) and c.get("item") == u["id"] for c in classes.values())]
    if pending:
        lines.append(f"- {t('ed_pending', language).format(n=len(pending))}")
    out = ([f"### {t('ed_title', language)}", ""] + lines + [""]) if lines else []
    if undecided_lines:
        # The classes with neither a read nor a reason, under the report's
        # undecided heading and lead: the run stopped before they were
        # decided; a person must decide. Said the same at report time and
        # at exit.
        out += [f"### {t('ed_undecided_title', language)}", "", t("ed_undecided_lead", language).format(
            n=len(undecided_lines)), ""] + undecided_lines + [""]
    try:
        # Depth of analysis per host: how many classes of each cost tier
        # are decided (core.evidence_depth), stated, never gated.
        from core.evidence_depth import TIERS, depth_by_host
        depth = depth_by_host(case_dir, ledger)
        rows = [(h, d) for h, d in depth.items() if not host or h.casefold() == host.casefold()]
        if rows:
            out += [f"### {t('ed_depth_title', language)}", "", t("ed_depth_lead", language), ""]
            for h, d in sorted(rows):
                out.append(f"- {h or t('ed_no_host', language)}: " + ", ".join(
                    f"{t('ed_tier_' + tier, language)} {d[tier][0]}/{d[tier][1]}" for tier in TIERS if d[tier][1]))
            out.append("")
    except Exception:  # noqa: BLE001
        pass
    return out


@_locked
def credit_dispositions(case_dir: str | os.PathLike) -> list[str]:
    """Set read and partial from the evidence, never from the model: an
    image's class is read when the index shows every live entry of it read,
    partial when some are; a collected tree's or a loose file's class the
    same by its own files' reads (a file a parser only processed is parsed,
    never read); a memory item's structure class is read when a plugin of
    that structure ran on it; an item is read when every class is read or
    left with at least one read, partial when any is read or partial. Left
    units are never changed. Returns the changed unit ids."""
    from core.coverage_ledger import load_ledger, save_ledger
    ledger = load_ledger(case_dir)
    if ledger.get("classes") is None:
        return []
    classes = ledger.get("classes") or {}
    changed: list[str] = []
    calls = None
    try:
        from core.contents_index import read_state_by_class
        items = {k: i for k, i in (ledger.get("items") or {}).items() if isinstance(i, dict) and i.get("path")}
        with_classes = {c.get("item") for c in classes.values() if isinstance(c, dict)}
        trees = [i for k, i in items.items() if i.get("kind") in ("tree", "file") and k in with_classes]
        members: dict[str, dict[str, list[str]]] = {}
        if trees:
            # The profile's files, as the ledger build gave them to the classes.
            from core.evidence_profile import ensure_evidence_profile
            files = ensure_evidence_profile(str(case_dir)).get("files") or []
            members = {i["path"]: {label: [rel for rel, _e in m] for label, m in _tree_members(i, files).items()}
                       for i in trees}
        by_image = read_state_by_class(case_dir, [i["path"] for i in items.values() if i.get("kind") == "image"],
                                       *([members] if members else []))
    except Exception:  # noqa: BLE001
        by_image = {}
    for iid, item in (ledger.get("items") or {}).items():
        if not isinstance(item, dict):
            continue
        own = [c for c in classes.values() if isinstance(c, dict) and c.get("item") == iid]
        if item.get("kind") == "image":
            counts = by_image.get(item.get("path")) or {}
            for c in own:
                if _credit_class(c, counts.get(c["label"]) or {}):
                    changed.append(c["id"])
        elif item.get("kind") in ("tree", "file") and own:
            # A collected tree's or a loose file's class by the reads of its
            # own files, under the image's rule (read_state_by_class ``files``).
            # The members are the ones the class was built from; when the
            # profile no longer gives that many (the folder changed since the
            # ledger was built) no read makes it whole: partial at most, until
            # the next ledger build counts it again.
            counts = by_image.get(item.get("path")) or {}
            for c in own:
                n = counts.get(c["label"]) or {}
                if _credit_class(c, n, whole=n.get("total") == int(c.get("files") or 0)):
                    changed.append(c["id"])
        elif item.get("kind") == "memory":
            # What ran on this image: the memory batch's answers, and every
            # plugin a call ran on it (a scan asked for on request, or the
            # trace alone when the batch has no status for the image). Only
            # calls that ran Volatility count: a wrapper's own record
            # ("<py>:") may be an answer deferred to the batch, never a read.
            if calls is None:
                calls = _successful_calls(case_dir)
            name = str(item["path"]).rsplit("/", 1)[-1].lower()
            ran = " ".join((_batch_ran(case_dir, item) or [])
                           + [text for text in calls if name in text and not text.startswith("<py>:")])
            for c in own:
                plugins = MEMORY_STRUCTURES.get(c["label"]) or ()
                hit = {p for p in plugins if re.search(rf"(?<![a-z]){p}(?![a-z])", ran)}
                if not hit or c.get("state") not in ("pending", "relevant", "walked"):
                    continue
                if any(memory_cost(p) == "scan" for p in hit):
                    c.update(state="read", reason="a scan of this structure ran on the image")
                elif c.get("state") != "walked":
                    # A walk misses what was unlinked or freed: read only
                    # once the structure's scan ran.
                    c.update(state="walked", reason="a walk of this structure ran; its scan did not")
                else:
                    continue
                changed.append(c["id"])
        if not own and item.get("state") in ("pending", "relevant") and item.get("read_by"):
            # An item with no content classes is read when a call read its
            # content (the ledger's contact record), never by a listing.
            item.update(state="read", reason="a call read its content", read_from=item.get("state"),
                        proof_call_ids=[(item.get("read_by") or {}).get("call_id")])
            changed.append(iid)
        elif (not own and item.get("state") == "read" and not item.get("read_by")
              and item.get("reason") == "a call read its content"):
            # That record is gone (a recount found no call that read it, a
            # failed read blocked it): the item is back where it stood.
            item.update(state=item.pop("read_from", None) or "relevant", reason="", proof_call_ids=[])
            changed.append(iid)
        if own and item.get("state") in ("pending", "relevant", "partial"):
            states = {c.get("state") for c in own}
            if states <= {"read", "left"} and "read" in states:
                item.update(state="read", reason="every class read or left")
                changed.append(iid)
            elif states & {"read", "partial", "walked"} and item.get("state") != "partial":
                item.update(state="partial", reason="some classes read")
                changed.append(iid)
    try:
        changed += _code_no_reader(case_dir, ledger)       # the format's fact first
        if (ledger.get("meta") or {}).pop("code_no_reader_marked", False):
            changed.append("meta:code_no_reader")          # the classes' key marks are ledger state
        changed += _code_unreadable(case_dir, ledger)
    except Exception:  # noqa: BLE001 - a code leave that cannot run leaves the class open
        pass
    try:
        # The cost band of each class, fixed when first tiered (a failed
        # reader moves it to hard): core.evidence_depth.
        from core.evidence_depth import class_tiers
        before = {cid: c.get("tier") for cid, c in classes.items() if isinstance(c, dict)}
        class_tiers(case_dir, ledger, store=True)
        changed += [cid for cid, c in classes.items() if isinstance(c, dict) and c.get("tier") != before.get(cid)]
    except Exception:  # noqa: BLE001 - a band that cannot be computed is computed when read
        pass
    if changed:
        save_ledger(case_dir, ledger)
    return changed


def _code_unreadable(case_dir, ledger: dict[str, Any]) -> list[str]:
    """Leave as unreadable, by code, the open classes whose item gained
    failed reads since the last pass: the proposal is the new failed calls
    that name the item, the verdict is check_leave's (two failed calls by
    readers that take the format, no successful one). Runs only when the
    trace gained a failed read past the cursor the ledger's meta keeps, so
    a call-time pass costs nothing while nothing failed. Returns the ids
    left."""
    from core.coverage_ledger import failed_read_attempt
    from core.evidence_leave import _leave, check_leave, code_leaves_on
    from core.execution_log import log
    if not code_leaves_on():
        return []
    meta = ledger.setdefault("meta", {})
    cursor = int(meta.get("code_leave_cursor") or 0)
    with log._lock:
        entries = [e for e in log._entries if e.get("type") == "tool_call"
                   and int(e.get("call_id") or 0) > cursor]
    if not entries:
        return []
    meta["code_leave_cursor"] = max(int(e.get("call_id") or 0) for e in entries)
    failed = [e for e in entries if failed_read_attempt(e)]
    if not failed:
        return []
    out: list[str] = []
    items = ledger.get("items") or {}
    for c in list((ledger.get("classes") or {}).values()):
        if not isinstance(c, dict) or c.get("state") not in ("pending", "relevant"):
            continue
        item = items.get(c.get("item")) or {}
        base = str(item.get("path") or "").rsplit("/", 1)[-1]
        proof = [int(e["call_id"]) for e in failed
                 if base and base in str(e.get("cmd") or "") + str(e.get("args") or "")]
        if len(proof) < 2:
            continue
        reason = "by code: the readers that take its format failed on it (calls " + ", ".join(map(str, proof[:6])) + ")"
        verdict = check_leave(case_dir, ledger, c["id"], "unreadable", reason, proof, by_code=True)
        if verdict["ok"]:
            _leave(case_dir, c, "unreadable", reason, proof, verdict)
            out.append(c["id"])
    return out


def code_no_reader_key(case_dir, ledger: dict[str, Any]) -> str:
    """What a no_reader verdict rests on, as one digest: the attacker
    entities and the hosts' exports with their versions (the sweep), and
    the listing generation (the member names the readers are resolved by;
    the registry does not change within a run). A class checked at a key
    carries it; while the key stands, its verdict would come out the same
    and it is not checked again (a credited read elsewhere changes no
    other class's verdict)."""
    import hashlib
    import json
    try:
        from core.contents_index import listing_generation
        from core.evidence_leave import attacker_entities, exports_of_hosts
        root = Path(case_dir)
        hosts = sorted({str(i.get("host") or "") for i in (ledger.get("items") or {}).values()
                        if isinstance(i, dict) and i.get("host")})
        exports = []
        for e, _n in exports_of_hosts(case_dir, hosts):
            try:
                st = (root / e).stat()
                exports.append([e, st.st_mtime_ns, st.st_size])
            except OSError:
                exports.append([e, 0, 0])
        parts = [attacker_entities(case_dir), exports, listing_generation(case_dir)]
    except Exception:  # noqa: BLE001 - a key that cannot be computed never skips the pass
        return ""
    return hashlib.sha1(json.dumps(parts, ensure_ascii=False, default=str).encode("utf-8")).hexdigest()


def _code_no_reader(case_dir, ledger: dict[str, Any]) -> list[str]:
    """Leave as no_reader, by code, the open classes whose format is known
    and declared by no registered reader (core.evidence_leave.unit_readers:
    an unknown format never counts). An open class is checked when it does
    not carry the current key (code_no_reader_key: the attacker entities,
    the exports and their versions, the listing generation): a class the
    pass checked at this key, either way, is not checked again; a class
    opened again (a reopen) or newly built is. Never again for a ledger
    save alone."""
    from core.evidence_leave import _leave, attacker_entities, check_leave, code_leaves_on
    if not code_leaves_on():
        return []
    meta = ledger.setdefault("meta", {})
    meta.pop("code_no_reader_at", None)
    key = code_no_reader_key(case_dir, ledger)
    due = [c for c in (ledger.get("classes") or {}).values()
           if isinstance(c, dict) and c.get("state") in ("pending", "relevant")
           and not (key and c.get("no_reader_key") == key)]
    if not due:
        return []
    out: list[str] = []
    ctx = {"attacker": attacker_entities(case_dir)}        # one attacker set for the pass
    for c in due:
        item = (ledger.get("items") or {}).get(c.get("item")) or {}
        if item.get("kind") == "memory":
            continue
        reason = "by code: no registered reader declares the format of its files"
        verdict = check_leave(case_dir, ledger, c["id"], "no_reader", reason, [], ctx=ctx, by_code=True)
        if verdict["ok"]:
            _leave(case_dir, c, "no_reader", reason, [], verdict)
            out.append(c["id"])
        if key:
            c["no_reader_key"] = key
    meta["code_no_reader_key"] = key
    meta["code_no_reader_marked"] = bool(key)              # marks to save, also when nothing was left
    return out


def _credit_class(c: dict[str, Any], n: dict[str, Any], *, whole: bool = True) -> bool:
    """Set a class's read, partial or parsed state (in place) from its files'
    counts (core.contents_index.read_state_by_class); whether it changed.
    ``whole``: the counts cover every member the class was built with. A
    partial class moves on with its reads (its count, then read: files are
    read one call at a time) and is never taken back to parsed here."""
    state = c.get("state")
    if state not in ("pending", "relevant", "parsed", "partial") or not n.get("total"):
        return False
    if state == "partial" and not (n["read"] or n["partial"]):
        return False
    if n["read"] == n["total"] and whole:
        c.update(state="read", reason=f"all {n['total']} files read")
    elif n["read"] or n["partial"]:
        credited = f"{n['read']:,} of {n['total']:,} files read" + (
            f", {n['partial']:,} partly" if n["partial"] else "")
        if state == "partial" and c.get("credited") == credited:
            return False
        c.update(state="partial", reason=credited, credited=credited)
    elif n.get("parsed"):
        # Open, with its next step: the rows are in the outputs.
        outputs = list(n.get("outputs") or [])
        filters = list(n.get("filters") or [])
        # A parse that kept no output file (none named in its report) has
        # no rows to query: its step is a parse into an output or a read.
        reason = ((f"{n['parsed']:,} of {n['total']:,} files parsed into {', '.join(outputs[:3])}"
                   if outputs else f"{n['parsed']:,} of {n['total']:,} files parsed into no output file")
                  + (f" (parsed with {'; '.join(filters[:2])} only)" if filters else "")
                  + (", no row looked at" if outputs else
                     ": parse them into an output or read them, or leave it with that reason"))
        if c.get("state") == "parsed" and c.get("reason") == reason:
            return False
        c.update(state="parsed", reason=reason, outputs=outputs, parse_filters=filters, no_rows=False,
                 overwritten=[], from_state=c.get("from_state") or c.get("state"))
    elif n.get("no_rows"):
        # Open, and no output holds a row of it: the step is a
        # parse without the filter, or a leave with that reason.
        filters = list(n.get("no_rows_filters") or [])
        reason = (f"0 rows matched {'; '.join(filters[:2]) or 'the parse'} in {n['no_rows']:,} of "
                  f"{n['total']:,} files: parse without the filter, or leave it with that reason")
        if c.get("state") == "parsed" and c.get("reason") == reason:
            return False
        c.update(state="parsed", reason=reason, outputs=[], parse_filters=filters, no_rows=True,
                 overwritten=[], from_state=c.get("from_state") or c.get("state"))
    elif n.get("overwritten"):
        # Open, and its rows are in no output: the output it was
        # parsed into was written over by a later parse.
        gone = list(n.get("overwritten_outputs") or [])
        reason = (f"{n['overwritten']:,} of {n['total']:,} files parsed into {', '.join(gone[:3])}, which "
                  "a later parse wrote over: parse them again into an output of their own, or leave it "
                  "with that reason")
        if c.get("state") == "parsed" and c.get("reason") == reason:
            return False
        c.update(state="parsed", reason=reason, outputs=[], parse_filters=[], no_rows=False,
                 overwritten=gone, from_state=c.get("from_state") or c.get("state"))
    else:
        return False
    return True


def _batch_ran(case_dir, item: dict[str, Any]) -> list[str] | None:
    """The plugins the memory batch ran to an answer on the item's image
    (core.memory_batch), None when the batch is off."""
    try:
        from core import memory_batch as MB
        if not MB.batch_on():
            return None
        target = os.path.realpath(os.path.join(str(case_dir), str(item["path"])))
        images = MB.status(case_dir).get("images") or {}
        mine = next((v for k, v in images.items() if os.path.realpath(k) == target), {}) or {}
        return [p.lower() for p, st in (mine.get("plugins") or {}).items() if st == "done"]
    except Exception:  # noqa: BLE001
        return None


def _successful_calls(case_dir) -> list[str]:
    """The command and arguments of each successful tool call, lowercased,
    each call as the read rule sees it (a background job's start counts by
    the job's outcome, core.coverage_ledger.resolved_entry)."""
    try:
        from core.coverage_ledger import resolved_entry
        from core.execution_log import trace_entries
        jobs: dict = {}
        calls = (resolved_entry(case_dir, e, jobs) for e in trace_entries(case_dir) or []
                 if e.get("type") == "tool_call")
        return [(str(e.get("cmd") or "") + " " + str(e.get("args") or "")).lower()
                for e in calls if e is not None and e.get("success") is not False]
    except Exception:  # noqa: BLE001
        return []
