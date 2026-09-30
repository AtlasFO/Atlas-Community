"""Machine-readable exports: ATT&CK Navigator layer + STIX 2.1 / CSV IOCs.

A SOC should never retype indicators out of a Markdown report. These tools
render the trace's findings into an ATT&CK Navigator layer (technique heat
map) and a STIX 2.1 bundle / flat CSV of IOCs for SIEM/EDR/firewall import.

Both output shapes are external specifications — the ATT&CK Navigator layer
schema and STIX 2.1 — so what a writer for them looks like is largely decided
before any is written. Emitting these two in the first place follows Mulder
(Apache-2.0, commit 1246de42, report/navigator.py and report/ioc_export.py);
what goes into them is Atlas's:
- Techniques come from the gate-validated `validated_techniques` channel;
  bare T-IDs found in descriptions are included but marked unvalidated in the
  layer comment, so a reader can tell which provenance each one has.
- IOC eligibility follows Atlas's confidence tiers: CONFIRMED/LIKELY only.
- Indicator extraction is Atlas's own, from the finding text.
- The STIX relationship runs indicator --indicates--> attack-pattern, which
  is what the specification defines; Mulder's ran from its identity object in
  both code paths. Each indicator is related to the attack-patterns of the
  SAME finding, so every edge is evidence-grounded rather than decorative.
The bundle is built stdlib-only; when the optional `stix2` library is
installed it is used as a validation pass, never as a hard dependency.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastmcp import FastMCP

from core import output_safe
from core.paths import assert_output_safe

mcp = FastMCP("export")

# Confidence tier → Navigator score/color (Mulder used report severities;
# Atlas's tiers are the graded equivalent).
_TIER_SCORE = {"CONFIRMED": 100, "LIKELY": 75, "SUSPECTED": 50,
               "UNCONFIRMED": 25}
_TIER_COLOR = {"CONFIRMED": "#ff0000", "LIKELY": "#ff6600",
               "SUSPECTED": "#ffff00", "UNCONFIRMED": "#66ccff"}
_TIER_ORDER = {"CONFIRMED": 0, "LIKELY": 1, "SUSPECTED": 2,
               "UNCONFIRMED": 3}

_IOC_TIERS = {"CONFIRMED", "LIKELY"}

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# ── IOC extraction (Atlas-side; Mulder's lives in its renderer) ──────────────

_IOC_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
    ("url", re.compile(r"\bhttps?://[^\s'\"<>)\]]+")),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("ipv4", re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")),
    # Conservative TLD allowlist — a broad domain regex drowns the export
    # in filenames and prose abbreviations.
    ("domain", re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
        r"(?:com|net|org|io|ru|cn|de|info|biz|onion|xyz|top|cc|me|co|uk|"
        r"fr|nl|eu|su|ws|tk)\b", re.IGNORECASE)),
)

_STIX_PATTERNS = {
    "ipv4": "[ipv4-addr:value = '{v}']",
    "ipv6": "[ipv6-addr:value = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "url": "[url:value = '{v}']",
    "md5": "[file:hashes.MD5 = '{v}']",
    "sha1": "[file:hashes.'SHA-1' = '{v}']",
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "email": "[email-addr:value = '{v}']",
}


def _findings(trace_path: Optional[str] = None) -> tuple[str, list[dict]]:
    """(case_id, finding entries) from a trace file or the live log.

    Only findings the run still asserts: an indicator from a withdrawn
    claim does not belong in the IOC export or the ATT&CK layer."""
    from core.claim_graph import asserted_finding_entries
    if trace_path:
        with open(trace_path, encoding="utf-8") as f:
            data = json.load(f)
        # The trace lives in the case's analysis/ directory.
        case_dir = os.path.dirname(os.path.dirname(os.path.abspath(trace_path)))
        return (data.get("case_id") or "case",
                asserted_finding_entries(
                    [e for e in data.get("entries", []) if e.get("type") == "finding"],
                    case_dir))
    from core.execution_log import log
    return (log._case_id or "case",
            asserted_finding_entries(
                [e for e in log._entries if e.get("type") == "finding"],
                log.case_dir()))


def extract_iocs(findings: list[dict]) -> list[dict]:
    """Classified IOCs from CONFIRMED/LIKELY finding descriptions.

    Each IOC carries its tier, a description snippet as context, and the
    finding's call_id so the export stays citable.
    """
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for f in findings:
        tier = (f.get("confidence") or "").upper()
        if tier not in _IOC_TIERS:
            continue
        desc = str(f.get("description") or "")
        claimed: list[tuple[int, int]] = []  # spans already matched
        for ioc_type, rx in _IOC_PATTERNS:
            for m in rx.finditer(desc):
                span = (m.start(), m.end())
                # hashes/urls/emails claim their span so the looser ipv4/
                # domain patterns don't re-match fragments of them
                if any(s <= span[0] and span[1] <= e for s, e in claimed):
                    continue
                claimed.append(span)
                value = m.group(0)
                key = (ioc_type, value.lower())
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "type": ioc_type, "value": value, "severity": tier,
                    "context": desc[:160],
                    "finding_call_id": f.get("call_id"),
                })
    return out


def _finding_techniques(f: dict) -> list[dict]:
    """[{tid, name, validated}] for one finding — the gate-validated
    channel first, then bare description T-IDs."""
    out: list[dict] = []
    seen: set[str] = set()
    for vt in (f.get("validated_techniques") or []):
        tid = str((vt.get("technique_id") if isinstance(vt, dict) else vt)
                  or "").upper()
        if tid and tid not in seen:
            seen.add(tid)
            name = (vt.get("name") if isinstance(vt, dict) else "") or tid
            out.append({"tid": tid, "name": name, "validated": True})
    for tid in _TID_RE.findall(str(f.get("description") or "")):
        tid = tid.upper()
        if tid not in seen:
            seen.add(tid)
            out.append({"tid": tid, "name": tid, "validated": False})
    return out


# ── ATT&CK Navigator layer ───────────────────────────────────────────────────

def build_navigator_layer(case_id: str, findings: list[dict],
                          domain: str = "enterprise-attack") -> dict:
    """Navigator layer: techniques scored/colored by the highest-tier
    finding that carries them; comments cite finding descriptions and flag
    unvalidated (description-only) technique IDs."""
    tmap: dict[str, dict] = {}
    for f in findings:
        tier = (f.get("confidence") or "UNCONFIRMED").upper()
        if tier not in _TIER_ORDER:
            tier = "UNCONFIRMED"
        for tech in _finding_techniques(f):
            cur = tmap.setdefault(tech["tid"], {
                "tier": tier, "validated": tech["validated"],
                "comments": []})
            if _TIER_ORDER[tier] < _TIER_ORDER[cur["tier"]]:
                cur["tier"] = tier
            cur["validated"] = cur["validated"] or tech["validated"]
            snippet = str(f.get("description") or "")[:100]
            if snippet and snippet not in cur["comments"]:
                cur["comments"].append(snippet)

    techniques = []
    for tid, data in sorted(tmap.items()):
        comment = "; ".join(data["comments"][:5])
        if not data["validated"]:
            comment = "(unvalidated T-ID from description) " + comment
        entry = {
            "techniqueID": tid,
            "score": _TIER_SCORE[data["tier"]],
            "color": _TIER_COLOR[data["tier"]],
            "comment": comment,
            "enabled": True,
        }
        if "." in tid:
            entry["showSubtechniques"] = True
        techniques.append(entry)

    return {
        "name": f"Atlas Investigation: {case_id}",
        "versions": {"attack": "16", "navigator": "4.5", "layer": "4.5"},
        "domain": domain,
        "description": (f"Techniques observed during investigation "
                        f"{case_id}; scored by finding confidence tier"),
        "sorting": 3,
        "layout": {"layout": "side", "showName": True, "showID": True},
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66ccff", "#ffff00", "#ff6600",
                       "#ff0000"],
            "minValue": 0, "maxValue": 100,
        },
    }


# ── STIX 2.1 bundle ──────────────────────────────────────────────────────────

def build_stix_bundle(case_id: str, findings: list[dict]) -> dict:
    """STIX 2.1 bundle: identity, one indicator per unique IOC, one
    attack-pattern per unique technique, and indicator --indicates-->
    attack-pattern relationships for IOC/technique pairs that co-occur in
    the same finding (Mulder's identity-as-source_ref bug fixed)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity_id = f"identity--{uuid.uuid4()}"
    objects: list[dict] = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id,
        "created": now, "modified": now,
        "name": f"Atlas Investigation {case_id}",
        "identity_class": "system",
    }]

    indicator_ids: dict[str, str] = {}   # pattern → id
    ap_ids: dict[str, str] = {}          # tid → id
    rel_seen: set[tuple[str, str]] = set()

    for f in findings:
        if (f.get("confidence") or "").upper() not in _IOC_TIERS:
            continue
        f_iocs = extract_iocs([f])
        techs = _finding_techniques(f)

        f_indicator_ids = []
        for ioc in f_iocs:
            tmpl = _STIX_PATTERNS.get(ioc["type"])
            if not tmpl:
                continue
            pattern = tmpl.format(v=ioc["value"].replace("'", "\\'"))
            if pattern not in indicator_ids:
                ind_id = f"indicator--{uuid.uuid4()}"
                indicator_ids[pattern] = ind_id
                objects.append({
                    "type": "indicator", "spec_version": "2.1",
                    "id": ind_id, "created": now, "modified": now,
                    "name": ioc["value"], "pattern": pattern,
                    "pattern_type": "stix", "valid_from": now,
                    "created_by_ref": identity_id,
                    "labels": ["malicious-activity"],
                })
            f_indicator_ids.append(indicator_ids[pattern])

        f_ap_ids = []
        for tech in techs:
            tid = tech["tid"]
            if tid not in ap_ids:
                ap_id = f"attack-pattern--{uuid.uuid4()}"
                ap_ids[tid] = ap_id
                objects.append({
                    "type": "attack-pattern", "spec_version": "2.1",
                    "id": ap_id, "created": now, "modified": now,
                    "name": tech["name"],
                    "external_references": [{
                        "source_name": "mitre-attack",
                        "external_id": tid,
                        "url": (f"https://attack.mitre.org/techniques/"
                                f"{tid.replace('.', '/')}/"),
                    }],
                })
            f_ap_ids.append(ap_ids[tid])

        # indicator --indicates--> attack-pattern, only for pairs grounded
        # in the same finding (STIX 2.1 semantics; the Mulder bug fix).
        for ind_id in f_indicator_ids:
            for ap_id in f_ap_ids:
                if (ind_id, ap_id) in rel_seen:
                    continue
                rel_seen.add((ind_id, ap_id))
                objects.append({
                    "type": "relationship", "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created": now, "modified": now,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": ap_id,
                })

    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}",
              "objects": objects}
    _stix2_validate(bundle)
    return bundle


def _stix2_validate(bundle: dict) -> None:
    """Optional validation pass when the stix2 library is installed —
    never a hard dependency, never fatal."""
    try:
        import stix2
        stix2.parse(json.dumps(bundle), allow_custom=True)
    except ImportError:
        pass
    except Exception as e:
        import sys
        print(f"[Atlas WARN] stix2 validation flagged the bundle: {e}",
              file=sys.stderr)


def build_ioc_csv(iocs: list[dict]) -> str:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=[
        "type", "value", "severity", "context", "finding_call_id"])
    writer.writeheader()
    for ioc in iocs:
        writer.writerow(ioc)
    return out.getvalue()


# ── file writers (shared by the MCP tools and the atlas report CLI) ──────────

def write_navigator(case_id: str, findings: list[dict], output_dir: str,
                    domain: str = "enterprise-attack") -> dict:
    layer = build_navigator_layer(case_id, findings, domain=domain)
    if not layer["techniques"]:
        return {"success": False, "techniques": 0,
                "error": ("no technique IDs on any finding — map findings "
                          "with correlate.mitre_map / mitre_validate "
                          "first")}
    assert_output_safe(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"{case_id}.navigator.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)
    return {"success": True, "path": path,
            "techniques": len(layer["techniques"])}


def write_iocs(case_id: str, findings: list[dict], output_dir: str,
               fmt: str = "all") -> dict:
    assert_output_safe(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    iocs = extract_iocs(findings)
    result: dict = {"success": True, "ioc_count": len(iocs),
                    "stix_path": None, "csv_path": None}
    if not iocs:
        result["note"] = ("no IOCs extracted from CONFIRMED/LIKELY "
                          "findings")
    if fmt in ("csv", "all"):
        path = os.path.join(output_dir, f"{case_id}.iocs.csv")
        with open(path, "w", encoding="utf-8") as f:
            f.write(build_ioc_csv(iocs))
        result["csv_path"] = path
    if fmt in ("stix", "all"):
        bundle = build_stix_bundle(case_id, findings)
        path = os.path.join(output_dir, f"{case_id}.iocs.stix.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)
        result["stix_path"] = path
        result["stix_objects"] = len(bundle["objects"])
    return result


# ── MCP tools ────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def export_navigator(output_dir: str = "exports",
                     domain: str = "enterprise-attack") -> dict:
    """
    Write a MITRE ATT&CK Navigator layer (<case_id>.navigator.json) from
    the current findings — techniques scored by finding confidence tier,
    gate-validated technique IDs first-class. Load it at
    https://mitre-attack.github.io/attack-navigator/. Run after findings
    are mapped (correlate.mitre_map / mitre_validate), typically alongside
    the final report.
    """
    case_id, findings = _findings()
    return write_navigator(case_id, findings, output_dir, domain=domain)


@mcp.tool()
@output_safe
def export_iocs(output_dir: str = "exports", fmt: str = "all") -> dict:
    """
    Export IOCs from CONFIRMED/LIKELY findings as a STIX 2.1 bundle and/or
    flat CSV (fmt: "stix" | "csv" | "all") for SIEM/EDR/firewall import.
    Indicators keep their finding call_id (CSV) and are related to the
    attack-patterns of the same finding (STIX), so the export stays
    citable. Run alongside the final report.
    """
    if fmt not in ("stix", "csv", "all"):
        return {"success": False,
                "error": f"fmt must be stix|csv|all, got {fmt!r}"}
    case_id, findings = _findings()
    return write_iocs(case_id, findings, output_dir, fmt=fmt)
