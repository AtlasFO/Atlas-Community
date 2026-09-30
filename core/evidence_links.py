"""CASE.md Evidence Links — investigator host/path map for Atlas.

CASE.md stays the work inbox. An optional ``## Evidence Links`` section
gives a *simple* host ↔ path ↔ kind map so Plane A / orchestrator / brief
do not invent layouts or confuse the host names a log export uses with
image folder names.

User-facing format (table preferred):

```markdown
## Evidence Links

| Label | Kind | Path | Notes |
|-------|------|------|-------|
| WS01 | disk | evidence/WS01/WS01.vmdk | VMware descriptor |
| ws01.example.local | alias | WS01 | the name the log exports use for WS01 |
| jane.doe | principal | | account under investigation |
| exports | tabular | evidence/ | case-root CSV/XLSX exports |
```

Bullet form also accepted:

```markdown
- WS01 | disk | evidence/WS01/WS01.vmdk | descriptor
- ws01 -> WS01 | alias | | name in the log exports
```

Kinds: ``disk``, ``memory``, ``pcap``, ``tabular``, ``evtx``, ``alias``,
``principal``, ``other`` (unknown kinds stored as ``other``).
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = "1.0"
LINKS_NAME = "evidence_links.json"

_SECTION_HEADINGS = frozenset({
    "evidence links",
    "evidence map",
    "evidence",
    "evidence files",
    "evidence sources",
    "hosts and evidence",
    "hosts & evidence",
    "evidence inventory",  # legacy heading — table/rows still useful as links
})

# An angle-bracket token is a template placeholder, never a host or a path.
_PLACEHOLDER_RE = re.compile(r"<[^<>\s]+>")
_HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*$")
_BULLET_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+(.+?)\s*$")
_ALIAS_ARROW_RE = re.compile(
    r"^\s*(.+?)\s*(?:->|→|=)\s*(.+?)\s*$"
)
_VALID_KINDS = frozenset({
    "disk", "memory", "pcap", "tabular", "evtx", "alias",
    "principal", "other", "file", "email", "live",
})


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def links_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / LINKS_NAME


def empty_links(case_id: str = "") -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id or "",
        "updated_at": _utcnow(),
        "source": "empty",
        "entries": [],
        "aliases": {},
        "hosts": [],
        "paths": [],
        "principals": [],
    }


def load_evidence_links(case_dir: str | os.PathLike) -> dict[str, Any]:
    path = links_path(case_dir)
    if not path.is_file():
        return empty_links(Path(case_dir).name)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty_links(Path(case_dir).name)
    if not isinstance(data, dict):
        return empty_links()
    data.setdefault("entries", [])
    data.setdefault("aliases", {})
    data.setdefault("hosts", [])
    data.setdefault("paths", [])
    data.setdefault("principals", [])
    return data


def save_evidence_links(
    case_dir: str | os.PathLike, data: dict[str, Any],
) -> Path:
    root = Path(case_dir).resolve()
    path = links_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(data)
    payload["schema_version"] = SCHEMA_VERSION
    payload["case_id"] = payload.get("case_id") or root.name
    payload["updated_at"] = _utcnow()
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def _norm_kind(kind: str) -> str:
    k = (kind or "other").strip().casefold().replace(" ", "_")
    aliases = {
        "image": "disk",
        "vmdk": "disk",
        "e01": "disk",
        "hdd": "disk",
        "csv": "tabular",
        "xlsx": "tabular",
        "logs": "tabular",
        "eventlog": "evtx",
        "winevt": "evtx",
        "user": "principal",
        "account": "principal",
        "identity": "principal",
        "aka": "alias",
        "same_as": "alias",
    }
    k = aliases.get(k, k)
    return k if k in _VALID_KINDS else "other"


def _norm_path(path: str, case_dir: Optional[Path] = None) -> str:
    p = (path or "").strip().strip("`").replace("\\", "/")
    if not p or p in ("—", "-", "–", "n/a", "na", "."):
        return ""
    if p.startswith("./"):
        p = p[2:]
    # Absolute under case → make relative
    if case_dir and os.path.isabs(p):
        try:
            p = str(Path(p).resolve().relative_to(case_dir.resolve()))
        except Exception:
            pass
    if not p.startswith("evidence/") and not p.startswith("analysis/"):
        # bare relative like WS01/foo.vmdk or *.csv under evidence
        if "/" in p or p.endswith((".vmdk", ".e01", ".csv", ".tsv", ".xlsx",
                                   ".evtx", ".pcap", ".mem", ".raw", ".dd")):
            p = f"evidence/{p}" if not p.startswith("evidence") else p
    return p


def _split_row_cells(line: str) -> list[str]:
    s = line.strip()
    if not s.startswith("|"):
        return []
    parts = [c.strip() for c in s.strip("|").split("|")]
    return parts


def _is_separator_row(cells: list[str]) -> bool:
    if not cells:
        return False
    return all(re.fullmatch(r":?-{3,}:?", c or "") for c in cells)


def _parse_entry(
    label: str,
    kind: str,
    path: str,
    notes: str = "",
    *,
    case_dir: Optional[Path] = None,
) -> Optional[dict[str, Any]]:
    label = (label or "").strip().strip("`")
    if _PLACEHOLDER_RE.search(label) or _PLACEHOLDER_RE.search(path or ""):
        return None            # a template example row (<HOST>, <image>), not a link
    kind_n = _norm_kind(kind)
    notes = (notes or "").strip()
    path_n = _norm_path(path, case_dir)

    # Alias shorthand in label: "ws01 -> WS01"
    if kind_n == "alias" or "->" in label or "→" in label or (
            kind_n == "other" and _ALIAS_ARROW_RE.match(label)):
        m = _ALIAS_ARROW_RE.match(label)
        if m:
            return {
                "label": m.group(1).strip(),
                "kind": "alias",
                "path": "",
                "alias_of": m.group(2).strip(),
                "notes": notes,
            }
        if path_n and not path_n.startswith("evidence/"):
            # path column holds canonical host
            return {
                "label": label,
                "kind": "alias",
                "path": "",
                "alias_of": path.strip().strip("`"),
                "notes": notes,
            }

    if kind_n == "alias" and path_n and not path_n.startswith("evidence/"):
        return {
            "label": label,
            "kind": "alias",
            "path": "",
            "alias_of": path.strip().strip("`"),
            "notes": notes,
        }

    if not label:
        return None
    return {
        "label": label,
        "kind": kind_n,
        "path": path_n,
        "alias_of": "",
        "notes": notes,
    }


def parse_evidence_links(
    markdown: str,
    *,
    case_dir: Optional[str | os.PathLike] = None,
) -> dict[str, Any]:
    """Parse Evidence Links section from CASE.md markdown text."""
    root = Path(case_dir).resolve() if case_dir else None
    entries: list[dict[str, Any]] = []
    in_section = False
    saw_table_header = False

    # Strip HTML comments / fenced examples (same rules as investigation requests)
    try:
        from core.investigation_tasks import _strip_noncontent_markdown
        body = _strip_noncontent_markdown(markdown or "")
    except Exception:
        body = markdown or ""

    for raw in body.splitlines():
        hm = _HEADING_RE.match(raw)
        if hm:
            title = hm.group(1).strip().casefold()
            # strip trailing punctuation / emphasis
            title = title.rstrip(":").strip().strip("*_ ")
            if title in _SECTION_HEADINGS:
                in_section = True
                saw_table_header = False
                continue
            if in_section:
                # next heading ends the section
                break
            continue
        if not in_section:
            continue
        if not raw.strip():
            continue

        cells = _split_row_cells(raw)
        if cells:
            if _is_separator_row(cells):
                continue
            # header row
            low = [c.casefold() for c in cells]
            if any(h in low for h in ("label", "host", "kind", "path")) and (
                    "kind" in low or "path" in low or "type" in low):
                saw_table_header = True
                continue
            # data row: Label | Kind | Path | Notes
            while len(cells) < 4:
                cells.append("")
            label, kind, path, notes = cells[0], cells[1], cells[2], cells[3]
            # Allow Host | Path | Notes (kind inferred)
            if not kind and path:
                kind = "other"
            if saw_table_header or label:
                ent = _parse_entry(label, kind, path, notes, case_dir=root)
                if ent:
                    entries.append(ent)
            continue

        bm = _BULLET_RE.match(raw)
        if bm:
            body = bm.group(1).strip()
            # alias arrow form first
            if "|" not in body and _ALIAS_ARROW_RE.match(body):
                m = _ALIAS_ARROW_RE.match(body)
                assert m
                entries.append({
                    "label": m.group(1).strip(),
                    "kind": "alias",
                    "path": "",
                    "alias_of": m.group(2).strip(),
                    "notes": "",
                })
                continue
            parts = [p.strip() for p in body.split("|")]
            while len(parts) < 4:
                parts.append("")
            ent = _parse_entry(
                parts[0], parts[1], parts[2], parts[3], case_dir=root,
            )
            if ent:
                entries.append(ent)

    aliases: dict[str, str] = {}
    hosts: list[str] = []
    paths: list[str] = []
    principals: list[str] = []
    for e in entries:
        lab = e.get("label") or ""
        if e.get("kind") == "alias":
            dest = e.get("alias_of") or ""
            if lab and dest:
                aliases[lab] = dest
            continue
        if e.get("kind") == "principal":
            if lab and lab not in principals:
                principals.append(lab)
            continue
        if lab and e.get("kind") in (
                "disk", "memory", "pcap", "evtx", "tabular", "file", "other"):
            if lab not in hosts and e.get("kind") != "principal":
                # label may be a bundle name (a set of exports) — still useful as host/focus
                if re.search(r"[A-Za-z]", lab) and len(lab) <= 64:
                    if lab not in hosts:
                        hosts.append(lab)
        p = e.get("path") or ""
        if p and p not in paths:
            paths.append(p)

    # Canonical hosts: alias targets first, then labels with disk/memory paths
    canonical: list[str] = []
    for e in entries:
        if e.get("kind") == "disk" and e.get("label"):
            if e["label"] not in canonical:
                canonical.append(e["label"])
    for dest in aliases.values():
        if dest not in canonical:
            canonical.append(dest)

    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": root.name if root else "",
        "updated_at": _utcnow(),
        "source": "CASE.md",
        "entries": entries,
        "aliases": aliases,
        "hosts": canonical or hosts,
        "paths": paths,
        "principals": principals,
    }


def read_case_md(case_dir: str | os.PathLike) -> str:
    root = Path(case_dir).resolve()
    for name in ("CASE.md", "CLAUDE.md"):
        p = root / name
        if p.is_file():
            try:
                return p.read_text(encoding="utf-8")
            except OSError:
                continue
    return ""


def sync_evidence_links(
    case_dir: str | os.PathLike,
    *,
    persist: bool = True,
) -> dict[str, Any]:
    """Parse CASE.md Evidence Links and optionally persist to .atlas/."""
    root = Path(case_dir).resolve()
    md = read_case_md(root)
    data = parse_evidence_links(md, case_dir=root)
    data["case_id"] = root.name
    if persist:
        save_evidence_links(root, data)
    return data


def linked_paths(case_dir: str | os.PathLike) -> list[str]:
    return list(load_evidence_links(case_dir).get("paths") or [])


def linked_hosts(case_dir: str | os.PathLike) -> list[str]:
    data = load_evidence_links(case_dir)
    hosts = list(data.get("hosts") or [])
    # Include alias sources so affinity on the host names logs use still works
    for src in (data.get("aliases") or {}):
        if src not in hosts:
            hosts.append(src)
    return hosts


def resolve_host_label(
    case_dir: str | os.PathLike, name: str,
) -> str:
    """Map alias → canonical host label (identity if unknown)."""
    if not name:
        return ""
    aliases = load_evidence_links(case_dir).get("aliases") or {}
    # case-insensitive lookup
    for src, dest in aliases.items():
        if src.casefold() == name.casefold():
            return dest
    return name


def host_for_image(image_path: str, case_dir: str | os.PathLike) -> str:
    """The host label an image belongs to, from the Evidence Links: the
    label of a linked path that names the image or a directory above it,
    else a linked host label spelled inside the image's path; empty when
    the links say nothing (an image's stem is not a host name)."""
    raw = str(image_path or "").replace("\\", "/").rstrip("/")
    if not raw:
        return ""
    # The case directory's own name is not evidence: match on the path
    # inside the case (taken before folding case, so the directory's own
    # spelling is stripped).
    if raw.startswith("/"):
        try:
            raw = Path(raw).resolve().relative_to(Path(case_dir).resolve()).as_posix()
        except (ValueError, OSError):
            pass
    low = raw.casefold()
    data = load_evidence_links(case_dir)
    for e in data.get("entries") or []:
        label = str(e.get("label") or "")
        p = str(e.get("path") or "").replace("\\", "/").casefold().rstrip("/")
        if not label or not p or e.get("kind") in ("alias", "principal"):
            continue
        if low == p or low.endswith("/" + p) or low.startswith(p + "/") or ("/" + p + "/") in low:
            return label
    # A label as a whole token of the path, longest label first, so WS10's
    # image is not WS1's.
    for h in sorted(linked_hosts(case_dir), key=len, reverse=True):
        if h and len(h) >= 3 and re.search(
                r"(?<![a-z0-9])" + re.escape(h.casefold()) + r"(?![a-z0-9])", low):
            return str(h)
    return ""


def path_link_boost(path: str, case_dir: str | os.PathLike) -> float:
    """Score boost when a candidate path is declared in Evidence Links."""
    if not path:
        return 0.0
    low = path.replace("\\", "/").casefold()
    boost = 0.0
    for lp in linked_paths(case_dir):
        ll = lp.replace("\\", "/").casefold()
        if not ll:
            continue
        if low == ll or low.endswith("/" + ll) or ll.endswith("/" + Path(low).name):
            boost = max(boost, 8.0)
        elif ll.rstrip("/") in low or low in ll:
            boost = max(boost, 5.0)
    # host folder affinity from labels
    for h in linked_hosts(case_dir):
        if h and len(h) >= 3 and h.casefold() in low:
            boost = max(boost, 3.0)
    return boost


def format_links_for_brief(data: dict[str, Any] | None) -> list[str]:
    """Markdown bullets for the Rerun Brief."""
    data = data or {}
    entries = data.get("entries") or []
    if not entries:
        return [
            "(none — add a `## Evidence Links` table in CASE.md to bind "
            "hosts/paths for the investigator)",
        ]
    lines: list[str] = []
    for e in entries:
        lab = e.get("label") or "?"
        kind = e.get("kind") or "other"
        if kind == "alias":
            lines.append(
                f"- **{lab}** → `{e.get('alias_of')}` (alias)"
                + (f" — {e['notes']}" if e.get("notes") else "")
            )
        elif kind == "principal":
            lines.append(
                f"- **{lab}** (principal)"
                + (f" — {e['notes']}" if e.get("notes") else "")
            )
        else:
            path = e.get("path") or "—"
            lines.append(
                f"- **{lab}** [{kind}] `{path}`"
                + (f" — {e['notes']}" if e.get("notes") else "")
            )
    aliases = data.get("aliases") or {}
    if aliases:
        lines.append("")
        lines.append(
            "Use canonical host labels from this map when recording "
            "`host=` on findings. Do not invent paths outside these links "
            "without discovery."
        )
    return lines
