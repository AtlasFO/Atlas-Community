"""Readers that turn an operator's indicator file into threat-context rows.

A reader takes a path and yields plain dicts with a ``value`` and, when the
format carries them, ``type``, ``description``, ``confidence``, ``tlp``,
``first_seen``, ``last_seen``, ``malicious`` and ``labels``. Rows are
typed, normalised and judged fit or unfit in core.threat_context, never
here. Built in: one value per line, CSV with a header, STIX 2.1 bundles,
MISP event JSON and the native interchange (one JSON row per line, see
docs/intel.md). An organisation adds a format of its own as an addon
method marked ``@intel_reader`` (core.addons); addon readers are found
through the same discovery as every other addon.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any, Callable, Iterable

from core.indicators import _MAC_RE, refang

_HASH_RE = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}")
_REG_RE = re.compile(r"(?i)^(?:hkey_[a-z_]+|hklm|hkcu|hku|hkcr|hkcc)\\")


def detect_type(value: str) -> str:
    """The indicator type an untyped value reads as; ``pattern`` when
    nothing narrower fits."""
    from core.entities import extract
    from core.indicators import _delegated_host
    v = refang((value or "").strip())
    low = v.lower()
    if re.match(r"(?i)^[a-z][a-z0-9+.-]*://", v):
        return "url"
    if "@" in v and " " not in v:
        return "email"
    try:
        ipaddress.ip_network(v.strip("[]"), strict=False)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+:\d+", v):
        return "ip"
    if _HASH_RE.fullmatch(low):
        return "hash"
    if _MAC_RE.match(low):
        return "mac"
    if _REG_RE.match(v):
        return "registry"
    if "\\" in v or "/" in v:
        return "path"
    if "." in v and " " not in v and _delegated_host(low):
        return "domain"
    if any(e.startswith("file:") for e in extract(v)):
        return "file"
    return "pattern"


# ── built-in formats ─────────────────────────────────────────────────────

def read_lines(path: str | os.PathLike) -> Iterable[dict[str, Any]]:
    """One value per line. A line starting with ``#`` is a comment, and so
    is the rest of a line after whitespace and ``#`` (a URL keeps its
    fragment)."""
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if line.lstrip().startswith("#"):
            continue
        value = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        if value:
            yield {"value": value}


_CSV_COLUMNS = {
    "value": ("value", "indicator", "ioc", "observable", "ioc_value", "indicator_value"),
    "type": ("type", "indicator_type", "ioc_type", "kind", "observable_type"),
    "description": ("description", "comment", "comments", "notes", "context", "title"),
    "confidence": ("confidence", "score", "threat_score"),
    "tlp": ("tlp", "tlp_level", "marking"),
    "first_seen": ("first_seen", "firstseen", "created"),
    "last_seen": ("last_seen", "lastseen", "modified", "updated"),
    "malicious": ("malicious", "is_malicious"),
    "labels": ("labels", "tags"),
}


def _col_key(name: str) -> str:
    return re.sub(r"[\s-]+", "_", (name or "").strip().lower())


def read_csv(path: str | os.PathLike, mapping: dict[str, str] | None = None) -> Iterable[dict[str, Any]]:
    """A table with a header. Columns are found by their common names;
    ``mapping`` (field -> column name) overrides that."""
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    head = text[:4096]
    if str(path).lower().endswith(".tsv"):
        dialect: Any = "excel-tab"
    else:
        try:
            dialect = csv.Sniffer().sniff(head, delimiters=",;\t|")
        except csv.Error:
            dialect = "excel"
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    headers = reader.fieldnames or []
    by_key = {_col_key(h): h for h in headers}
    cols: dict[str, str] = {}
    for field, names in _CSV_COLUMNS.items():
        for n in names:
            if n in by_key:
                cols[field] = by_key[n]
                break
    for field, col in (mapping or {}).items():
        if col not in headers:
            raise ValueError(f"no column {col!r} in {Path(path).name} (columns: {', '.join(headers)})")
        cols[field] = col
    if "value" not in cols:
        if len(headers) != 1:
            raise ValueError(f"no value column in {Path(path).name}; name it with --map value=<column> "
                             f"(columns: {', '.join(headers)})")
        cols["value"] = headers[0]
    for rec in reader:
        row = {field: (rec.get(col) or "").strip() for field, col in cols.items()}
        if row.get("labels"):
            row["labels"] = [x.strip() for x in re.split(r"[;,|]", row["labels"]) if x.strip()]
        if row["value"]:
            yield row


# STIX 2.1: cyber-observable objects and the simple comparisons of an
# indicator pattern. The TLP marking definitions are the standard ones.
_STIX_OBJECTS = {
    "ipv4-addr": ("ip", "value"), "ipv6-addr": ("ip", "value"), "domain-name": ("domain", "value"),
    "url": ("url", "value"), "email-addr": ("email", "value"), "mac-addr": ("mac", "value"),
    "windows-registry-key": ("registry", "key"), "directory": ("path", "path"),
    "user-account": ("account", "account_login"), "mutex": ("pattern", "name"),
}
_STIX_TLP = {
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487": "clear",
    "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb": "green",
    "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9d78a": "amber",
    "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003": "amber+strict",
    "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1": "red",
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "clear",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
}
_STIX_TERM_RE = re.compile(r"\[\s*([a-z0-9-]+):([A-Za-z0-9_.'-]+)\s*=\s*'((?:[^'\\]|\\.)*)'\s*\]")


def _stix_term(obj: str, prop: str, value: str) -> dict[str, Any] | None:
    value = value.replace("\\'", "'").replace("\\\\", "\\")
    if obj == "file":
        if prop.startswith("hashes."):
            return {"type": "hash", "value": value}
        if prop == "name":
            return {"type": "file", "value": value}
        return None
    kind, attr = _STIX_OBJECTS.get(obj, ("", ""))
    return {"type": kind, "value": value} if kind and prop == attr else None


def _stix_meta(o: dict[str, Any], tlp_of: dict[str, str]) -> dict[str, Any]:
    labels = [str(x) for x in (o.get("labels") or []) + (o.get("indicator_types") or [])]
    tlp = next((tlp_of[m] for m in o.get("object_marking_refs") or [] if m in tlp_of), None)
    return {"description": str(o.get("description") or o.get("name") or ""),
            "confidence": o.get("confidence"), "labels": labels, "tlp": tlp,
            "first_seen": o.get("valid_from") or o.get("first_observed"),
            "last_seen": o.get("valid_until") or o.get("last_observed"),
            "malicious": True if "malicious-activity" in labels else None}


def read_stix2(path: str | os.PathLike) -> Iterable[dict[str, Any]]:
    """A STIX 2.1 bundle. A pattern that is not a plain OR of equality
    comparisons is kept as an unfit row with its text, never guessed."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    objects = data.get("objects") if isinstance(data, dict) else data
    tlp_of = dict(_STIX_TLP)
    for o in objects or []:
        if isinstance(o, dict) and o.get("type") == "marking-definition":
            name = str(o.get("name") or "").lower().replace("tlp:", "").strip()
            if name in ("clear", "white", "green", "amber", "amber+strict", "red"):
                tlp_of[o.get("id")] = "clear" if name == "white" else name
    for o in objects or []:
        if not isinstance(o, dict):
            continue
        kind = o.get("type")
        if kind == "indicator":
            meta = _stix_meta(o, tlp_of)
            pattern = str(o.get("pattern") or "")
            terms = _STIX_TERM_RE.findall(pattern)
            rest = _STIX_TERM_RE.sub("", pattern).replace("OR", "").strip()
            rows = [_stix_term(*t) for t in terms]
            if not terms or rest or not all(rows):
                yield {**meta, "type": "pattern", "value": pattern[:300],
                       "unfit": "a STIX pattern that is not a plain OR of equality comparisons"}
                continue
            for r in rows:
                yield {**meta, **r}
        elif kind == "file":
            meta = _stix_meta(o, tlp_of)
            for h in (o.get("hashes") or {}).values():
                yield {**meta, "type": "hash", "value": str(h)}
            if o.get("name"):
                yield {**meta, "type": "file", "value": str(o["name"])}
        elif kind in _STIX_OBJECTS:
            atlas_kind, attr = _STIX_OBJECTS[kind]
            if o.get(attr):
                yield {**_stix_meta(o, tlp_of), "type": atlas_kind, "value": str(o[attr])}


# MISP: attribute types mapped to the Atlas vocabulary; a composite type
# gives one row per part.
_MISP_TYPES = {
    "ip-src": "ip", "ip-dst": "ip", "domain": "domain", "hostname": "host", "url": "url", "uri": "url",
    "link": "url", "email": "email", "email-src": "email", "email-dst": "email", "target-email": "email",
    "md5": "hash", "sha1": "hash", "sha256": "hash", "filename": "file", "regkey": "registry",
    "mutex": "pattern", "user-agent": "pattern", "mac-address": "mac", "target-user": "account",
    "target-machine": "host",
}
_MISP_COMPOSITE = {
    "ip-src|port": ("ip", None), "ip-dst|port": ("ip", None), "hostname|port": ("host", None),
    "domain|ip": ("domain", "ip"), "filename|md5": ("file", "hash"), "filename|sha1": ("file", "hash"),
    "filename|sha256": ("file", "hash"), "regkey|value": ("registry", None),
}


def _misp_tlp(tags: Any) -> str | None:
    for t in tags or []:
        name = str((t or {}).get("name") or "").lower()
        if name.startswith("tlp:"):
            v = name[4:].strip()
            return "clear" if v == "white" else v
    return None


def _misp_attr(a: dict[str, Any], event_tlp: str | None, event_info: str) -> Iterable[dict[str, Any]]:
    kind, value = str(a.get("type") or ""), str(a.get("value") or "")
    meta = {"description": str(a.get("comment") or event_info or ""),
            "tlp": _misp_tlp(a.get("Tag")) or event_tlp,
            "first_seen": a.get("first_seen"), "last_seen": a.get("last_seen"),
            "malicious": True if a.get("to_ids") in (True, "1", 1) else None,
            "labels": [str(t.get("name")) for t in a.get("Tag") or [] if isinstance(t, dict)]}
    if kind in _MISP_TYPES:
        yield {**meta, "type": _MISP_TYPES[kind], "value": value}
    elif kind in _MISP_COMPOSITE and "|" in value:
        left, right = value.split("|", 1)
        lk, rk = _MISP_COMPOSITE[kind]
        yield {**meta, "type": lk, "value": left}
        if rk:
            yield {**meta, "type": rk, "value": right}
    else:
        yield {**meta, "type": "pattern", "value": value[:300], "unfit": f"MISP type {kind!r} has no Atlas type"}


def read_misp(path: str | os.PathLike) -> Iterable[dict[str, Any]]:
    """MISP event JSON: one event, a list of them, or a search response."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "response" in data:
        data = data["response"]
    events = data if isinstance(data, list) else [data]
    for ev in events:
        ev = ev.get("Event", ev) if isinstance(ev, dict) else {}
        tlp, info = _misp_tlp(ev.get("Tag")), str(ev.get("info") or "")
        for a in ev.get("Attribute") or []:
            yield from _misp_attr(a, tlp, info)
        for obj in ev.get("Object") or []:
            for a in (obj or {}).get("Attribute") or []:
                yield from _misp_attr(a, tlp, info)


def read_jsonl(path: str | os.PathLike) -> Iterable[dict[str, Any]]:
    """The native interchange: one JSON object per line (docs/intel.md)."""
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"line {n} is not a JSON object")
            yield row


BUILTIN: dict[str, dict[str, Any]] = {
    "lines": {"read": read_lines, "suffixes": (".txt", ".ioc", ".lst", ".list")},
    "csv": {"read": read_csv, "suffixes": (".csv", ".tsv")},
    "stix2": {"read": read_stix2, "suffixes": ()},
    "misp": {"read": read_misp, "suffixes": ()},
    "atlas-jsonl": {"read": read_jsonl, "suffixes": (".jsonl",)},
}


def readers() -> dict[str, dict[str, Any]]:
    """Every reader by name: the built-in ones, then enabled addons'."""
    out = dict(BUILTIN)
    try:
        from core.plugins import intel_readers
        for name, r in intel_readers().items():
            out.setdefault(name, r)
    except Exception:  # noqa: BLE001 - a broken addon must not hide the built-ins
        pass
    return out


def detect_format(path: str | os.PathLike, available: dict[str, dict[str, Any]] | None = None) -> str:
    """The reader for a file, from an addon's suffixes, then the file's
    shape (a STIX bundle, a MISP event), then its suffix."""
    available = available or readers()
    low = str(path).lower()
    for name, r in available.items():
        if name not in BUILTIN and any(low.endswith(s) for s in r.get("suffixes") or ()):
            return name
    if low.endswith(".json"):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return ""
        if isinstance(data, dict) and data.get("type") == "bundle":
            return "stix2"
        if isinstance(data, dict) and ("Event" in data or "response" in data) or (
                isinstance(data, list) and data and isinstance(data[0], dict) and "Event" in data[0]):
            return "misp"
        return ""
    for name in BUILTIN:
        if any(low.endswith(s) for s in BUILTIN[name]["suffixes"]):
            return name
    return "lines"


def read(path: str | os.PathLike, fmt: str | None = None,
         mapping: dict[str, str] | None = None) -> tuple[str, list[dict[str, Any]]]:
    """``(format, rows)`` for a file; raises ValueError for an unknown or
    undetectable format."""
    available = readers()
    fmt = fmt or detect_format(path, available)
    if fmt not in available:
        raise ValueError(f"unknown format {fmt!r} for {Path(path).name}; one of {', '.join(sorted(available))}")
    fn: Callable[..., Iterable[dict[str, Any]]] = available[fmt]["read"]
    rows = list(fn(path, mapping) if fmt == "csv" else fn(path))
    return fmt, [r for r in rows if isinstance(r, dict)]
