"""Published shared infrastructure: the edges and front ends a provider
publishes, and the vendors' own service names (ATLAS_IOC_SHARED_EDGE).

An address in a published edge range serves every site behind the edge, and
a vendor's service name serves every tenant of the service: an attacker row
on one of them is hunted, never blocked, because the name the attacker used
(the tenant, the path, the account) is the block item. The lists are
vendored in share/.common/shared_infrastructure.json, built by
devtools/build_shared_infrastructure.py from the publishers' own files, so
a run needs no network. Nothing here is case knowledge.

Names are matched exactly (the host as written, or without a leading
"www."), never by suffix: a tenant's name on a platform the vendor runs
("<tenant>.<platform>") stays unmarked, because it is the attacker's name.
"""
from __future__ import annotations

import bisect
import functools
import ipaddress
import json
import sys
from pathlib import Path
from typing import Any

PATH = Path(__file__).resolve().parents[1] / "share" / ".common" / "shared_infrastructure.json"
_WARNED: list[bool] = [False]


def shared_edge_on() -> bool:
    """ATLAS_IOC_SHARED_EDGE (default on)."""
    from core.envfile import env_flag
    return env_flag("ATLAS_IOC_SHARED_EDGE")


@functools.lru_cache(maxsize=4)
def _load(path: str) -> dict[str, Any] | None:
    """The vendored lists as lookup tables: per IP version a sorted list of
    (start, end, label) integer ranges, and name -> label for the vendor and
    the popular sets. None (warned once) when the file is missing or
    unreadable."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        if not _WARNED[0]:
            _WARNED[0] = True
            print(f"[Atlas WARN] shared infrastructure list missing or unreadable: {path}; "
                  "shared edges and vendor services are not marked", file=sys.stderr)
        return None
    ranges: dict[int, list[tuple[int, int, str]]] = {4: [], 6: []}
    for edge in data.get("edges") or []:
        label = str(edge.get("label") or "shared edge")
        for net in edge.get("networks") or []:
            try:
                n = ipaddress.ip_network(net, strict=False)
            except ValueError:
                continue
            ranges[n.version].append((int(n.network_address), int(n.broadcast_address), label))
    for v in ranges:
        # Disjoint ranges, so one bisect answers: an overlap keeps the first
        # label and extends the range.
        merged: list[tuple[int, int, str]] = []
        for start, end, label in sorted(ranges[v]):
            if merged and start <= merged[-1][1] + 1:
                s0, e0, l0 = merged[-1]
                merged[-1] = (s0, max(e0, end), l0)
            else:
                merged.append((start, end, label))
        ranges[v] = merged
    vendors = {str(name).lower(): label for label, names in (data.get("vendors") or {}).items()
               for name in names or []}
    popular = {str(name).lower(): label for label, names in (data.get("popular") or {}).items()
               for name in names or []}
    return {"ranges": ranges, "starts": {v: [r[0] for r in ranges[v]] for v in ranges},
            "vendors": vendors, "popular": popular, "built": str(data.get("built") or "")}


def missing() -> bool:
    """The vendored file could not be read."""
    return _load(str(PATH)) is None


def built() -> str:
    """When the vendored file was built ("" when missing)."""
    data = _load(str(PATH))
    return data["built"] if data else ""


def _edge(value: str, data: dict[str, Any]) -> str:
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return ""
    n = int(ip)
    i = bisect.bisect_right(data["starts"][ip.version], n) - 1
    if i >= 0:
        start, end, label = data["ranges"][ip.version][i]
        if start <= n <= end:
            return label
    return ""


def _host(kind: str, value: str) -> str:
    v = value.strip().lower()
    if kind == "url":
        v = v.split("://", 1)[-1].split("/", 1)[0].split("@")[-1].split(":")[0]
    elif kind == "email":
        v = v.rsplit("@", 1)[-1]
    return v.rstrip(".")


def mark(kind: str, value: str) -> dict[str, str] | None:
    """{"mark": "shared_edge" | "vendor_service" | "popular", "label"} for a
    value on the vendored lists, else None. An address is looked up in the
    edge ranges; the host of a domain, URL or mail address by exact name
    (or without a leading "www.") in the vendor set, then the popular set."""
    if not shared_edge_on():
        return None
    data = _load(str(PATH))
    if data is None:
        return None
    if kind == "ip":
        label = _edge(value, data)
        return {"mark": "shared_edge", "label": label} if label else None
    if kind not in ("domain", "url", "email", "host"):
        return None
    host = _host(kind, value)
    names = [host] + ([host[4:]] if host.startswith("www.") else [])
    for name in names:
        if name in data["vendors"]:
            return {"mark": "vendor_service", "label": data["vendors"][name]}
    for name in names:
        if name in data["popular"]:
            return {"mark": "popular", "label": data["popular"][name]}
    return None


def mark_text(m: dict[str, str] | None) -> str:
    """How a mark reads in the deliverables."""
    if not m:
        return ""
    if m["mark"] == "shared_edge":
        return f"shared edge ({m['label']})"
    if m["mark"] == "vendor_service":
        return f"vendor service ({m['label']})"
    return f"popular name ({m['label']})"
