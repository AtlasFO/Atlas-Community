"""Fetch + filter MITRE CTI enterprise-attack.json and write the local tables.

Usage:
    python -m tools.mitre.build_mitre_cache [--output-dir DIR] [--source URL]

The script:
  1. Downloads enterprise-attack.json from the maintained MITRE STIX repo
     (mitre-attack/attack-stix-data; the old mitre/cti repo is frozen).
  2. Filters live `attack-pattern` objects to DFIR-relevant tactics (drops
     Reconnaissance, Resource Development).
  3. ALSO keeps revoked/deprecated attack-patterns as validation-only entries
     (empty keywords, `status` + `superseded_by` fields). ATT&CK v19 revoked
     ~150 defense-evasion staples (T1562.x → T1685/T1686, T1070.001 →
     T1685.005); analysts trained on older matrices cite the historical IDs,
     and the evidence_strength gate must not refuse a real-but-superseded ID.
  4. Filters `intrusion-set` objects to those with non-empty aliases.
  5. Joins via `relationship` objects (`relationship_type == "uses"`) to build
     `{group_id: [technique_ids]}` map (live techniques only).
  6. MERGES into existing `mitre_techniques.json` — pre-existing live T-IDs
     retain their already-tuned keywords; new T-IDs get keywords from
     `tools/mitre/keywords.py`; a successor with no keywords inherits them
     from the technique(s) it superseded.
  7. Reads `course-of-action` objects and `mitigates` relationships into a
     mitigations table keyed both ways (mitigation → techniques,
     technique → mitigations) — the source of derived recommendations.
  8. Writes `mitre_techniques.json`, `mitre_groups.json`,
     `mitre_software.json` and `mitre_mitigations.json` under --output-dir.

Run once, commit the resulting JSON files. Do NOT bake live MITRE API calls
into the runtime — too slow and too flaky during a demo.
"""
from __future__ import annotations
import argparse
import datetime
import json
import os
import re
import sys
import urllib.request
from typing import Optional

MITRE_CTI_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

# DFIR-relevant tactics. Skip Reconnaissance / Resource Development entirely
# (those are pre-compromise and not observable from disk/memory forensics).
# `stealth` and `defense-impairment` are the ATT&CK v19 successors of
# `defense-evasion`; keep all three so pre-v19 bundles still build.
DFIR_TACTICS = {
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "stealth",
    "defense-impairment",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
}

DEFAULT_OUTPUT_DIR = os.path.expanduser("~/cases/.common")


def _tactic_human(name: str) -> str:
    """`credential-access` → `Credential Access`."""
    return " ".join(w.capitalize() for w in name.split("-"))


def _extract_technique_id(obj: dict) -> Optional[str]:
    """Pull the `T1059.001`-style id from a STIX object's external_references."""
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _extract_group_id(obj: dict) -> Optional[str]:
    """Pull the `G0050`-style id from a STIX intrusion-set's external_references."""
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _extract_software_id(obj: dict) -> Optional[str]:
    """Pull the `S0154`-style id from a STIX malware/tool's external_references."""
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _extract_mitigation_id(obj: dict) -> Optional[str]:
    """Pull the `M1053`-style id from a STIX course-of-action's external_references."""
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _load_existing_techniques(path: str) -> dict[str, dict]:
    """Read the existing mitre_techniques.json so we can preserve hand-tuned
    `keywords` for T-IDs that already had them. Returns {} if missing."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f).get("techniques", {}) or {}
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


def fetch(source_url: str) -> dict:
    print(f"[build_mitre_cache] downloading {source_url} ...", file=sys.stderr)
    with urllib.request.urlopen(source_url, timeout=60) as resp:
        data = json.load(resp)
    print(f"[build_mitre_cache] got {len(data.get('objects', []))} STIX objects", file=sys.stderr)
    return data


def extract_attack_version(stix: dict) -> str:
    """ATT&CK release version from the bundle's x-mitre-collection object."""
    for obj in stix.get("objects", []) or []:
        if obj.get("type") == "x-mitre-collection":
            v = obj.get("x_mitre_version")
            if v:
                return f"v{v}"
    return "unknown"


def build_tables(stix: dict, existing_techniques: dict) -> tuple[dict, dict, dict, dict]:
    """Return (techniques, groups, software, mitigations) tables as dicts."""
    from . import keywords as kw_mod

    objects = stix.get("objects", []) or []

    # Pass 1: collect techniques + groups + software by their STIX id to join.
    technique_by_stix_id: dict[str, dict] = {}
    retired_by_stix_id: dict[str, dict] = {}  # revoked/deprecated attack-patterns
    group_by_stix_id: dict[str, dict] = {}
    software_by_stix_id: dict[str, dict] = {}
    mitigation_by_stix_id: dict[str, dict] = {}

    for obj in objects:
        otype = obj.get("type")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            # Retired techniques stay citable: real historical IDs must
            # validate (the gate exists to catch fabrications, not analysts
            # whose training data predates the latest ATT&CK restructure).
            # No tactic filter — an ID that ever existed should validate.
            if otype == "attack-pattern":
                tid = _extract_technique_id(obj)
                if tid:
                    phases = obj.get("kill_chain_phases", []) or []
                    tactics = sorted({
                        p.get("phase_name", "")
                        for p in phases
                        if p.get("kill_chain_name") == "mitre-attack"
                    })
                    retired_by_stix_id[obj["id"]] = {
                        "_tid": tid,
                        "name": obj.get("name", "")[:120],
                        "tactic": ", ".join(_tactic_human(t) for t in tactics),
                        "description": (obj.get("description", "") or "").split("\n", 1)[0][:400],
                        "status": "revoked" if obj.get("revoked") else "deprecated",
                    }
            continue
        if otype == "course-of-action":
            mid = _extract_mitigation_id(obj)
            # ATT&CK's own mitigation ids are M####; anything else under this
            # type is a legacy per-technique course of action and is skipped.
            if mid and re.fullmatch(r"M\d{4}", mid):
                mitigation_by_stix_id[obj["id"]] = {
                    "_mid": mid,
                    "name": obj.get("name", "")[:120],
                    "description": (obj.get("description", "") or "").split("\n", 1)[0][:400],
                    "technique_ids": [],
                }
            continue
        if otype in ("malware", "tool"):
            sid = _extract_software_id(obj)
            if not sid:
                continue
            name = obj.get("name", "")
            aliases = obj.get("x_mitre_aliases", []) or []
            software_by_stix_id[obj["id"]] = {
                "_sid": sid,
                "name": name[:120],
                "type": otype,  # 'malware' or 'tool'
                "aliases": [a for a in aliases if a != name][:20],
                "description": (obj.get("description", "") or "").split("\n", 1)[0][:400],
                "group_ids": [],
            }
        if otype == "attack-pattern":
            tid = _extract_technique_id(obj)
            if not tid:
                continue
            phases = obj.get("kill_chain_phases", []) or []
            tactics = sorted({
                p.get("phase_name", "")
                for p in phases
                if p.get("kill_chain_name") == "mitre-attack"
            })
            # Every live technique is kept so a real ID always validates;
            # the flag lets suggestion tools prefer what disk and memory
            # forensics can observe.
            tactic_human = ", ".join(_tactic_human(t) for t in tactics)
            technique_by_stix_id[obj["id"]] = {
                "_tid": tid,
                "name": obj.get("name", "")[:120],
                "tactic": tactic_human,
                "dfir_relevant": any(t in DFIR_TACTICS for t in tactics),
                "description": (obj.get("description", "") or "").split("\n", 1)[0][:400],
            }
        elif otype == "intrusion-set":
            aliases = obj.get("aliases", []) or []
            if not aliases:
                continue
            gid = _extract_group_id(obj)
            if not gid:
                continue
            group_by_stix_id[obj["id"]] = {
                "_gid": gid,
                "name": obj.get("name", "")[:120],
                "aliases": [a for a in aliases if a != obj.get("name", "")][:20],
                "description": (obj.get("description", "") or "").split("\n", 1)[0][:400],
                "technique_ids": [],
            }

    # Pass 2m: relationships → mitigation → [technique_ids] (live techniques)
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "mitigates":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        mit = mitigation_by_stix_id.get(obj.get("source_ref", ""))
        tech = technique_by_stix_id.get(obj.get("target_ref", ""))
        if mit and tech:
            mit["technique_ids"].append(tech["_tid"])

    # Pass 2a: relationships → group_id → [technique_ids]
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")
        group = group_by_stix_id.get(src)
        if not group:
            continue
        # A group `uses` either a technique or a piece of software.
        tech = technique_by_stix_id.get(tgt)
        if tech:
            group["technique_ids"].append(tech["_tid"])
            continue
        sw = software_by_stix_id.get(tgt)
        if sw:
            sw["group_ids"].append(group["_gid"])

    # Pass 2b: `revoked-by` relationships → old T-ID → successor T-ID.
    superseded_by: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "revoked-by":
            continue
        old = retired_by_stix_id.get(obj.get("source_ref", ""))
        new = technique_by_stix_id.get(obj.get("target_ref", ""))
        if old and new:
            superseded_by[old["_tid"]] = new["_tid"]

    # Build final dicts.
    techniques_out: dict[str, dict] = {}
    for stix_id, info in technique_by_stix_id.items():
        tid = info["_tid"]
        # Carry forward existing keywords; seed new T-IDs from the curated list.
        existing = existing_techniques.get(tid) or {}
        existing_kw = existing.get("keywords") if existing else None
        seed_kw = kw_mod.KEYWORD_SEEDS.get(tid, [])
        if existing_kw:
            keywords = existing_kw
        elif seed_kw:
            keywords = seed_kw
        else:
            keywords = []
        techniques_out[tid] = {
            "name": info["name"],
            "tactic": info["tactic"],
            "dfir_relevant": bool(info.get("dfir_relevant", True)),
            "description": info["description"],
            "keywords": keywords,
        }

    # A successor with no keywords of its own inherits from the technique(s)
    # it replaced (e.g. T1685.005 gets T1070.001's tuned event-log keywords),
    # so mitre_map keeps surfacing candidates across an ATT&CK renumbering.
    for old_tid, new_tid in superseded_by.items():
        new_entry = techniques_out.get(new_tid)
        if new_entry is None or new_entry["keywords"]:
            continue
        old_kw = (existing_techniques.get(old_tid) or {}).get("keywords") \
            or kw_mod.KEYWORD_SEEDS.get(old_tid, [])
        if old_kw:
            new_entry["keywords"] = list(old_kw)

    # Retired techniques: validation-only entries. Empty keywords keep them
    # out of mitre_map candidate ranking; `superseded_by` lets validate()
    # point the analyst at the current ID.
    for stix_id, info in retired_by_stix_id.items():
        tid = info["_tid"]
        if tid in techniques_out:
            continue  # a live object owns this ID; never shadow it
        techniques_out[tid] = {
            "name": info["name"],
            "tactic": info["tactic"],
            "description": info["description"],
            "keywords": [],
            "status": info["status"],
            "superseded_by": superseded_by.get(tid),
        }

    groups_out: dict[str, dict] = {}
    for stix_id, g in group_by_stix_id.items():
        gid = g["_gid"]
        # Sort + dedupe technique_ids for stable output
        tids = sorted(set(g["technique_ids"]))
        if not tids:
            continue
        groups_out[gid] = {
            "name": g["name"],
            "aliases": g["aliases"],
            "description": g["description"],
            "technique_ids": tids,
        }

    software_out: dict[str, dict] = {}
    for stix_id, s in software_by_stix_id.items():
        sid = s["_sid"]
        software_out[sid] = {
            "name": s["name"],
            "type": s["type"],
            "aliases": s["aliases"],
            "description": s["description"],
            "group_ids": sorted(set(s["group_ids"])),
        }

    mitigations_out: dict[str, dict] = {}
    by_technique: dict[str, list[str]] = {}
    for m_ in mitigation_by_stix_id.values():
        tids = sorted(set(m_["technique_ids"]))
        mitigations_out[m_["_mid"]] = {
            "name": m_["name"],
            "description": m_["description"],
            "technique_ids": tids,
        }
        for tid in tids:
            by_technique.setdefault(tid, []).append(m_["_mid"])
    for tid in by_technique:
        by_technique[tid].sort()
    return techniques_out, groups_out, software_out, {
        "mitigations": dict(sorted(mitigations_out.items())),
        "by_technique": dict(sorted(by_technique.items())),
    }


def write_outputs(output_dir: str, techniques: dict, groups: dict,
                  software: dict, source_url: str,
                  version: str = "unknown",
                  mitigations: Optional[dict] = None) -> None:
    os.makedirs(output_dir, exist_ok=True)
    built_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    techniques_path = os.path.join(output_dir, "mitre_techniques.json")
    groups_path = os.path.join(output_dir, "mitre_groups.json")
    software_path = os.path.join(output_dir, "mitre_software.json")

    techniques_doc = {
        "_meta": {
            "source": source_url,
            "version": version,
            "format": ("{technique_id: {name, tactic, description, keywords"
                       "[, status, superseded_by]}}"),
            "built_at": built_at,
        },
        "techniques": techniques,
    }
    groups_doc = {
        "_meta": {
            "source": source_url,
            "version": version,
            "format": "{group_id: {name, aliases, description, technique_ids}}",
            "built_at": built_at,
        },
        "groups": groups,
    }
    software_doc = {
        "_meta": {
            "source": source_url,
            "version": version,
            "format": "{software_id: {name, type, aliases, description, group_ids}}",
            "built_at": built_at,
        },
        "software": software,
    }

    mitigations_path = os.path.join(output_dir, "mitre_mitigations.json")
    mitigations_doc = {
        "_meta": {
            "source": source_url,
            "version": version,
            "format": ("{mitigations: {mitigation_id: {name, description, "
                       "technique_ids}}, by_technique: {technique_id: [mitigation_id]}}"),
            "built_at": built_at,
        },
        "mitigations": (mitigations or {}).get("mitigations", {}),
        "by_technique": (mitigations or {}).get("by_technique", {}),
    }

    # Pretty-print to keep diffs reviewable.
    with open(mitigations_path, "w") as f:
        json.dump(mitigations_doc, f, indent=2, sort_keys=True)
    with open(techniques_path, "w") as f:
        json.dump(techniques_doc, f, indent=2, sort_keys=True)
    with open(groups_path, "w") as f:
        json.dump(groups_doc, f, indent=2, sort_keys=True)
    with open(software_path, "w") as f:
        json.dump(software_doc, f, indent=2, sort_keys=True)

    print(f"[build_mitre_cache] wrote {len(techniques)} techniques → {techniques_path}", file=sys.stderr)
    print(f"[build_mitre_cache] wrote {len(groups)} groups → {groups_path}", file=sys.stderr)
    print(f"[build_mitre_cache] wrote {len(software)} software → {software_path}", file=sys.stderr)
    print(f"[build_mitre_cache] wrote {len(mitigations_doc['mitigations'])} mitigations → {mitigations_path}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Build MITRE ATT&CK cache for Atlas.")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--source", default=MITRE_CTI_URL)
    parser.add_argument("--input-file", help="Optional local STIX JSON to use instead of downloading")
    args = parser.parse_args()

    if args.input_file:
        with open(args.input_file) as f:
            stix = json.load(f)
    else:
        stix = fetch(args.source)

    existing_techniques_path = os.path.join(args.output_dir, "mitre_techniques.json")
    existing = _load_existing_techniques(existing_techniques_path)
    print(f"[build_mitre_cache] preserving keywords for {sum(1 for t in existing.values() if t.get('keywords'))} existing T-IDs", file=sys.stderr)

    version = extract_attack_version(stix)
    print(f"[build_mitre_cache] ATT&CK release: {version}", file=sys.stderr)
    techniques, groups, software, mitigations = build_tables(stix, existing)
    write_outputs(args.output_dir, techniques, groups, software, args.source, version,
                  mitigations=mitigations)


if __name__ == "__main__":
    main()
