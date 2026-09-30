"""The case's own assets: hosts, addresses, directory names, accounts and
device serials that belong to the examined system or the organisation
whose systems were attacked.

An indicator list that names the owner's own domain controller as hostile
infrastructure sends a responder to block their own server. Every value in
this set is an affected asset (incident frame) or a subject identifier
(subject frame), never a block or hunt item. Sources, each recorded on the
entry:

* the evidence links of the brief (labels, aliases, principal rows);
* the hosts of the current claims;
* brief tables under an evidence or system section, where a cue word (IP,
  serial, domain) binds a value to the host in the row's first cell; a
  table under any other heading may list the other side and is not read;
* closed appositions in the claims ("HOST (IP)", "IP (HOST)", "HOST at
  IP"), the one prose form that states identity rather than a relation;
  nothing binds across a clause boundary, on a bare comma, or when the
  clause marks the value as the other side's;
* special-use and private directory names (.local, .lan, .internal ...),
  which name the owner's own directory;
* the system baseline profile under analysis/baseline, when present.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

_IPV4 = r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4_RE = re.compile(r"(?<![\d.])" + _IPV4 + r"(?![\d.])")
_DOTTED = r"[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)+"
_SERIAL = r"[A-Za-z0-9][A-Za-z0-9_-]{7,}"
_OTHER_SIDE_RE = re.compile(
    r"(?i)\b(?:external|extern[ae]?|attacker(?:'s)?|angreifer\w*|c2|c&c|"
    r"command[- ]and[- ]control|remote|malicious|adversary|actor)\b")
_CLAUSE_END_RE = re.compile(r"[.!?](?=\s|$)|[;:](?=\s)|\n")
_DOMAIN_CUE_RE = re.compile(
    r"(?i)\b(?:domain|dom[aä]ne|realm|joined to(?: the domain)?)\W{1,3}(" + _DOTTED + r")")
_ESTATE_SECTIONS = frozenset({
    "evidence links", "evidence map", "evidence", "evidence files", "evidence sources",
    "hosts and evidence", "hosts & evidence", "evidence inventory", "target systems",
    "systems", "hosts", "systems in scope", "affected systems", "system inventory",
    "beweismittel", "systeme", "zielsysteme",
})
_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$")
_IP_CUE_RE = re.compile(r"(?i)\b(?:ip(?:v4)?(?: address)?|address|adresse)\b\W{0,4}(" + _IPV4 + r")")
_SERIAL_CUE_RE = re.compile(r"(?i)\b(?:serial(?: number| no\.?)?|s/n|seriennummer)\b\W{0,4}(" + _SERIAL + r")")
_TABLE_DOMAIN_RE = re.compile(r"(?i)\b(?:domain|dom[aä]ne)\b\W{0,4}(" + _DOTTED + r")")
_IP_HEADER_RE = re.compile(r"(?i)\b(?:ip|ipv4|address|adresse)\b")
_SERIAL_HEADER_RE = re.compile(r"(?i)\b(?:serial|s/n|seriennummer)\b")
# A "Domain" column of a hosts table names the owner's domain the same way an
# "IP" column names its addresses.
_DOMAIN_HEADER_RE = re.compile(r"(?i)\b(?:domain|dom(?:ä|ae)ne|dns)\b")
_DOMAIN_CELL_RE = re.compile(r"(?i)\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b")
_CURRENT = frozenset({"new", "supported", "confirmed", "needs_review", "reviewed", "conflict"})
_KINDS = ("ip", "host", "domain", "account", "serial")


def normalize(value: str, kind: str) -> str:
    v = str(value or "").strip().strip("`*'\"")
    if kind == "serial":
        return v.upper()
    return v if kind == "ip" else v.rstrip(".").casefold()


def _clause_bounds(text: str, pos: int) -> tuple[int, int]:
    lo = max([m.end() for m in _CLAUSE_END_RE.finditer(text, 0, pos)] or [0])
    nxt = _CLAUSE_END_RE.search(text, pos)
    return lo, (nxt.start() if nxt else len(text))


def _other_side(text: str, pos: int) -> bool:
    lo, _ = _clause_bounds(text, pos)
    return bool(_OTHER_SIDE_RE.search(" ".join(text[lo:pos].split()[-3:])))


def _forms(host: str) -> list[re.Pattern[str]]:
    h, ip = r"\b" + re.escape(host) + r"\b", r"(?P<ip>" + _IPV4 + r")"
    return [re.compile(p, re.I) for p in (
        rf"{h}\s*\(\s*(?:(?:ip|ipv4|address|adresse)\s*:?\s*)?{ip}\s*\)",
        rf"{ip}\s*\(\s*(?:(?:host|hostname|rechner)\s*:?\s*)?{h}\s*\)",
        rf"{h}\s+(?:at|has\s+(?:the\s+)?(?:ip\s+)?address|hat\s+die\s+(?:ip-?)?adresse)\s+{ip}\b",
        rf"\b(?:ip|ip address|address|adresse)\s+(?:of|von)\s+{h}\s+(?:is|ist)\s+{ip}\b",
        rf"{h}['’]s\s+(?:ip|ip address|address)\s+(?:is\s+)?{ip}\b")]


def bind_appositions(statement: str, hosts: Iterable[str]) -> list[tuple[str, str]]:
    """``(host, address)`` pairs the statement states as identities."""
    text, out = str(statement or ""), set()
    for host in filter(None, hosts):
        for rx in _forms(host):
            for m in rx.finditer(text):
                if not _CLAUSE_END_RE.search(m.group(0)) and not _other_side(text, m.start("ip")):
                    out.add((host, m.group("ip")))
    return sorted(out)


def _add(assets, kind, value, *, host="", source, claim_id=""):
    key = normalize(value, kind)
    if not key or len(key) > 128:
        return
    e = assets["values"].setdefault(f"{kind}:{key}", {
        "type": kind, "value": str(value).strip().strip("`*'\""), "host": host,
        "sources": [], "claim_ids": []})
    if source not in e["sources"]:
        e["sources"].append(source)
    if claim_id and claim_id not in e["claim_ids"]:
        e["claim_ids"].append(claim_id)
    e["host"] = e["host"] or host


def _from_links(case_dir, assets):
    try:
        from core.evidence_links import load_evidence_links
        entries = load_evidence_links(case_dir).get("entries") or []
    except Exception:  # noqa: BLE001
        return
    for e in entries:
        if not isinstance(e, dict) or not str(e.get("label") or "").strip():
            continue
        label, kind = str(e["label"]).strip(), str(e.get("kind") or "")
        if kind == "principal":
            _add(assets, "account", label, source="evidence_links")
        elif kind in ("disk", "memory", "live", "evtx", "pcap", "alias"):
            if re.search(r"[A-Za-z]", label) and len(label) <= 64:
                _add(assets, "host", label, host=label, source="evidence_links")
            dest = str(e.get("alias_of") or "").strip()
            if dest:
                _add(assets, "host", dest, host=dest, source="evidence_links")


def _nodes(case_dir):
    try:
        from core.claim_graph import load_graph
        nodes = (load_graph(case_dir).get("nodes") or {}).values()
    except Exception:  # noqa: BLE001
        return []
    return [n for n in nodes if isinstance(n, dict) and n.get("kind") in
            ("claim", "conclusion", "observation") and str(n.get("status") or "new") in _CURRENT]


def _heading(line: str) -> str | None:
    m = _HEADING_RE.match(line)
    if not m:
        return None
    title = re.sub(r"\s*\([^)]*\)\s*$", "", m.group(1).strip().strip("*_ ")).rstrip(":").strip()
    return title.casefold()


def _from_brief(case_dir, assets):
    try:
        from core.investigation_tasks import read_case_markdown
        text = read_case_markdown(case_dir) or ""
    except Exception:  # noqa: BLE001
        return
    allowed, header = False, None
    for line in text.splitlines():
        title = _heading(line)
        if title is not None:
            allowed, header = title in _ESTATE_SECTIONS, None
            continue
        s = line.strip()
        if not s.startswith("|"):
            header = None
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if all(re.fullmatch(r":?-{3,}:?", c or "") for c in cells):
            continue
        if header is None:
            header = cells
            continue
        host = cells[0].strip("`*_ ").strip() if cells else ""
        if not allowed or not host or len(host) > 64:
            continue
        _add(assets, "host", host, host=host, source="brief_table")
        for i, cell in enumerate(cells[1:], start=1):
            col = header[i] if i < len(header) else ""
            for m in _IP_CUE_RE.finditer(cell):
                _add(assets, "ip", m.group(1), host=host, source="brief_table")
            for m in _SERIAL_CUE_RE.finditer(cell):
                _add(assets, "serial", m.group(1), host=host, source="brief_table")
            for m in _TABLE_DOMAIN_RE.finditer(cell):
                _add(assets, "domain", m.group(1), host=host, source="brief_table")
            if _IP_HEADER_RE.search(col):
                for m in _IPV4_RE.finditer(cell):
                    _add(assets, "ip", m.group(0), host=host, source="brief_table")
            if _SERIAL_HEADER_RE.search(col):
                for m in re.finditer(r"\b" + _SERIAL + r"\b", cell):
                    _add(assets, "serial", m.group(0), host=host, source="brief_table")
            if _DOMAIN_HEADER_RE.search(col):
                for m in _DOMAIN_CELL_RE.finditer(cell):
                    if not re.fullmatch(r"[\d.]+", m.group(1)):
                        _add(assets, "domain", m.group(1), host=host, source="brief_table")


def _from_claims(nodes, assets):
    from core.ioc_catalog import _SPECIAL_USE_RE
    hosts = [e["value"] for e in assets["values"].values() if e["type"] == "host"]
    for n in nodes:
        text, nid, own = str(n.get("statement") or ""), str(n.get("id") or ""), str(n.get("host") or "")
        for host, ip in bind_appositions(text, hosts):
            _add(assets, "ip", ip, host=host, source="claim_apposition", claim_id=nid)
        for m in re.finditer(_DOTTED, text):
            if _SPECIAL_USE_RE.search(m.group(0)) and not _other_side(text, m.start()):
                _add(assets, "domain", m.group(0), host=own, source="directory_name", claim_id=nid)
        for m in _DOMAIN_CUE_RE.finditer(text):
            if _SPECIAL_USE_RE.search(m.group(1)) and not _other_side(text, m.start(1)):
                _add(assets, "domain", m.group(1), host=own, source="claim_apposition", claim_id=nid)


def _from_baseline(case_dir, assets):
    folder = Path(case_dir) / "analysis" / "baseline"
    for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        ident = data.get("identity") or {}
        host = str(ident.get("computer_name") or data.get("host") or path.stem).strip()
        _add(assets, "host", host, host=host, source="baseline")
        for key in ("domain", "primary_domain"):
            if ident.get(key):
                _add(assets, "domain", str(ident[key]), host=host, source="baseline")
        for iface in data.get("interfaces") or []:
            if not isinstance(iface, dict):
                continue
            for key in ("IPAddress", "DhcpIPAddress", "ip", "ipv4", "address"):
                vals = iface.get(key)
                for v in (vals if isinstance(vals, list) else [vals]):
                    v = str(v or "").strip()
                    if v and v != "0.0.0.0":
                        _add(assets, "ip", v, host=host, source="baseline")
        for acct in data.get("accounts") or []:
            name = acct.get("name") if isinstance(acct, dict) else acct
            if name:
                _add(assets, "account", str(name), host=host, source="baseline")
        for dev in data.get("usb") or []:
            serial = dev.get("serial") if isinstance(dev, dict) else dev
            if serial:
                _add(assets, "serial", str(serial), host=host, source="baseline")


def own_assets(case_dir: str | os.PathLike) -> dict[str, Any]:
    """Every own asset the sources yield, keyed ``type:normalised value``,
    plus the host list. Deterministic and side-effect free."""
    assets: dict[str, Any] = {"values": {}, "hosts": []}
    _from_links(case_dir, assets)
    nodes = _nodes(case_dir)
    for n in nodes:
        if str(n.get("host") or "").strip():
            _add(assets, "host", n["host"].strip(), host=n["host"].strip(), source="claim_hosts",
                 claim_id=str(n.get("id") or ""))
    _from_brief(case_dir, assets)
    _from_baseline(case_dir, assets)
    _from_claims(nodes, assets)
    assets["hosts"] = sorted({e["value"] for e in assets["values"].values() if e["type"] == "host"},
                             key=str.casefold)
    return assets


def lookup(assets: dict[str, Any], value: str, kind: str = "") -> dict[str, Any] | None:
    """The own-asset entry for ``value``, or None. A domain candidate also
    matches a host of the same name; an account matches by its bare name."""
    values = assets.get("values") or {}
    for k in ([kind] if kind else _KINDS):
        hit = values.get(f"{k}:{normalize(value, k)}")
        if hit:
            return hit
    if kind in ("domain", "host", ""):
        for k in ("host", "domain"):
            hit = values.get(f"{k}:{normalize(value, 'host')}")
            if hit:
                return hit
    if kind in ("account", ""):
        bare = normalize(value, "account").split("\\")[-1].split("@")[0]
        return values.get(f"account:{bare}")
    return None
