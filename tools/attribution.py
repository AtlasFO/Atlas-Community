"""Adversary attribution pipeline.

Given the accumulated CONFIRMED/LIKELY findings in the trace, extract MITRE
ATT&CK technique IDs, look them up against the local groups table, and rank
candidate threat-actor profiles by F1 + tactic diversity. Most autonomous IR
agents stop at "we saw T1059.001"; this closes the loop to
"this matches G0016 (APT29) with HIGH confidence."
"""
from __future__ import annotations
import json
import os
import re
from fastmcp import FastMCP

from core import output_safe
from tools.mitre import load_groups, load_software, load_techniques

mcp = FastMCP("attribution")

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Multi-signal fusion weights (echoed in the tool output). Technique overlap is
# the grounded primary signal; infra + malware are corroborating and bounded.
W_TECHNIQUE, W_INFRA, W_MALWARE = 0.6, 0.25, 0.15
_BAND_ORDER = ["INSUFFICIENT", "LOW", "MEDIUM", "HIGH"]

# Software aliases too generic to match on (would false-positive on ordinary
# report/finding prose).
_MALWARE_STOPWORDS = {
    "tool", "tools", "agent", "http", "https", "data", "file", "files",
    "test", "windows", "system", "remote", "service", "client", "server",
    "update", "microsoft", "shell", "python", "proxy",
    "loader", "stager", "payload", "backdoor", "downloader",
}


def _norm(s: str) -> str:
    """Normalize an actor/alias token for equality matching."""
    return re.sub(r"[^a-z0-9]", "", str(s or "").lower())


def _analysis_dir() -> "str | None":
    """Best-effort active-case analysis/ dir (parent of the trace path)."""
    trace_path = None
    try:
        from core.execution_log import log as _log
        trace_path = getattr(_log, "_path", None)
    except Exception:
        trace_path = None
    if not trace_path:
        return None
    d = os.path.dirname(os.path.abspath(trace_path))
    return d if os.path.isdir(d) else None


def _infra_actor_signals() -> list[tuple[str, str]]:
    """Actor-name signals from T2-3a enrichment sidecars.

    Reads <case>/analysis/enrichment/*.json (written by enrich.otx_lookup /
    enrich.misp_lookup) and returns (actor_token, evidence_label) pairs — OTX
    pulse adversaries and MISP threat-actor galaxy clusters. Empty when no
    sidecars exist, so caseless / offline runs contribute nothing.
    """
    base = _analysis_dir()
    if not base:
        return []
    enrich_dir = os.path.join(base, "enrichment")
    if not os.path.isdir(enrich_dir):
        return []
    signals: list[tuple[str, str]] = []
    for fn in sorted(os.listdir(enrich_dir)):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(enrich_dir, fn)) as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        ind = doc.get("indicator") or doc.get("value") or fn
        for adv in doc.get("adversaries") or []:
            signals.append((adv, f"OTX adversary '{adv}' on {ind}"))
        for cluster in doc.get("galaxy_clusters") or []:
            if (cluster.get("galaxy_type") or "").startswith("threat-actor"):
                val = cluster.get("value")
                if val:
                    signals.append((val, f"MISP galaxy '{val}' on {ind}"))
    return signals


def _malware_corpus(idx) -> str:
    """Finding descriptions + yara/capa/floss tool output — the text malware
    family names are matched against."""
    parts: list[str] = []
    for f in idx.by_type.get("finding", []):
        parts.append(f.get("description", "") or "")
    for e in idx.by_type.get("tool_call", []):
        cmd = (e.get("cmd") or "").lower()
        if any(m in cmd for m in ("yara", "capa", "floss")):
            parts.append(e.get("stdout_excerpt", "") or "")
    return "\n".join(parts)


def _malware_group_signals(corpus: str) -> dict[str, list[str]]:
    """Map group_id → malware-family evidence, from load_software() matches.

    A software alias (≥4 chars, word-boundary, not a stopword) appearing in the
    corpus attributes that family's ``group_ids``. Empty when the software table
    isn't built, so it degrades to zero contribution.
    """
    software = load_software().get("software", {}) or {}
    if not software or not corpus:
        return {}
    low = corpus.lower()
    out: dict[str, list[str]] = {}
    for sid, info in software.items():
        names = [info.get("name", "")] + list(info.get("aliases") or [])
        matched_alias = None
        for alias in names:
            a = (alias or "").strip()
            if len(a) < 4 or a.lower() in _MALWARE_STOPWORDS:
                continue
            if re.search(r"\b" + re.escape(a.lower()) + r"\b", low):
                matched_alias = a
                break
        if not matched_alias:
            continue
        label = f"malware family '{matched_alias}' ({sid})"
        for gid in info.get("group_ids") or []:
            out.setdefault(gid, []).append(label)
    return out


def _bump_band(base_band: str) -> str:
    """Raise a confidence band by exactly one step, capped at HIGH."""
    try:
        i = _BAND_ORDER.index(base_band)
    except ValueError:
        return base_band
    return _BAND_ORDER[min(i + 1, len(_BAND_ORDER) - 1)]


def _collect_observed_tids() -> tuple[set[str], int]:
    """Pull T-IDs from every finding in the trace. Returns (tids, finding_count)."""
    from core.execution_log import log
    idx = log.index()
    tids: set[str] = set()
    findings = idx.by_type.get("finding", [])
    for f in findings:
        # Only weight CONFIRMED/LIKELY for attribution scoring — SUSPECTED
        # and UNCONFIRMED tiers introduce too much noise.
        if (f.get("confidence") or "").upper() in {"CONFIRMED", "LIKELY"}:
            tids.update(_TID_RE.findall(f.get("description", "") or ""))
    return tids, len(findings)


def _tactic_count(tids: set[str], techniques: dict) -> int:
    """How many distinct tactics are covered by the observed T-IDs?"""
    tactics: set[str] = set()
    for tid in tids:
        info = techniques.get(tid)
        if not info:
            continue
        for t in (info.get("tactic") or "").split():
            tactics.add(t)
    return len(tactics)


# A technique used by more than this share of all profiled groups says
# little about which group it was: RDP, PsExec, scheduled tasks and data
# encryption are common to most ransomware operators.
COMMON_TECHNIQUE_SHARE = 0.10


def technique_group_counts(groups_table: dict) -> dict[str, int]:
    """``{technique_id: number of groups that use it}`` — how common each
    technique is across the profiled groups."""
    counts: dict[str, int] = {}
    for info in (groups_table or {}).values():
        for tid in set(info.get("technique_ids") or []):
            counts[tid] = counts.get(tid, 0) + 1
    return counts


def distinctive_techniques(overlap_set, group_counts: dict[str, int], n_groups: int) -> set[str]:
    """The overlapping techniques few groups share — the ones that carry
    attribution weight."""
    limit = max(1, int(n_groups * COMMON_TECHNIQUE_SHARE))
    return {t for t in overlap_set if group_counts.get(t, 0) <= limit}


def _classify_confidence(overlap: int, tactic_count: int, distinctive: int | None = None) -> str:
    """Confidence band from overlap and tactic diversity; when the count of
    distinctive techniques is known, MEDIUM needs one and HIGH needs two —
    generic overlap alone stops at LOW."""
    if distinctive is not None:
        if overlap >= 5 and tactic_count >= 3 and distinctive >= 2:
            return "HIGH"
        if overlap >= 3 and tactic_count >= 2 and distinctive >= 1:
            return "MEDIUM"
        if overlap >= 2:
            return "LOW"
        return "INSUFFICIENT"
    if overlap >= 5 and tactic_count >= 3:
        return "HIGH"
    if overlap >= 3 and tactic_count >= 2:
        return "MEDIUM"
    if overlap >= 2:
        return "LOW"
    return "INSUFFICIENT"


@mcp.tool()
@output_safe
def attribute_actors(
    top_n: int = 5,
    min_overlap: int = 2,
) -> dict:
    """
    Rank MITRE ATT&CK Groups by overlap with observed techniques in the trace.

    Walks all CONFIRMED/LIKELY findings, extracts T-IDs, computes per-group
    F1 (precision/recall over the group's known techniques) + tactic-diversity
    bonus, assigns a HIGH/MEDIUM/LOW confidence band per group.

    top_n: number of candidates to return (default 5).
    min_overlap: minimum overlap to consider (default 2; lower = noisier).

    Returns ranked candidate list with matched_techniques, missing_techniques,
    score, confidence_band, caveat. Use this BEFORE recording any finding that
    names a threat actor — the `attribution_required` gate refuses such
    findings without a backing attribute_actors call.
    """
    observed, finding_count = _collect_observed_tids()
    if not observed:
        return {
            "success": True,
            "observed_tid_count": 0,
            "finding_count": finding_count,
            "candidates": [],
            "table_size": 0,
            "note": "No T-IDs in CONFIRMED/LIKELY findings — record findings "
                    "with ATT&CK technique citations first.",
        }

    groups_table = load_groups().get("groups", {}) or {}
    techniques_table = load_techniques().get("techniques", {}) or {}
    if not groups_table:
        return {
            "success": False,
            "error": "MITRE groups table empty. Run "
                     "`python -m tools.mitre.build_mitre_cache` to populate.",
        }

    observed_tactic_count = _tactic_count(observed, techniques_table)

    # Corroborating signals (both empty when no sidecars / no software table, so
    # the fused ranking is byte-identical to the pure-F1 path in that case).
    from core.execution_log import log
    infra_signals = _infra_actor_signals()
    malware_by_group = _malware_group_signals(_malware_corpus(log.index()))

    candidates: list[dict] = []
    group_counts = technique_group_counts(groups_table)
    n_groups = len(groups_table)
    for gid, info in groups_table.items():
        gtids = set(info.get("technique_ids") or [])
        if not gtids:
            continue
        overlap_set = observed & gtids
        overlap = len(overlap_set)
        distinctive = distinctive_techniques(overlap_set, group_counts, n_groups)
        # Grounding: a group with no technique overlap NEVER appears, no matter
        # what infra/malware evidence names it.
        if overlap < min_overlap:
            continue
        precision = overlap / max(len(gtids), 1)
        recall = overlap / max(len(observed), 1)
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        # Tactic diversity bonus: 0.1 per distinct tactic represented in overlap
        overlap_tactic_count = _tactic_count(overlap_set, techniques_table)
        technique_score = round(f1 + 0.1 * overlap_tactic_count, 4)
        base_band = _classify_confidence(overlap, overlap_tactic_count, len(distinctive))
        if base_band == "INSUFFICIENT":
            continue

        # ── infra signal: sidecar actor names matching this group's aliases ──
        group_tokens = {_norm(info.get("name", ""))}
        group_tokens.update(_norm(a) for a in (info.get("aliases") or []))
        group_tokens.discard("")
        infra_evidence: list[str] = []
        for token, label in infra_signals:
            if _norm(token) in group_tokens:
                infra_evidence.append(label)
        infra_score = min(1.0, 0.5 * len(set(infra_evidence)))

        # ── malware signal: family tokens attributed to this group ──
        malware_evidence = list(dict.fromkeys(malware_by_group.get(gid, [])))
        malware_score = min(1.0, 0.5 * len(malware_evidence))

        fused_score = round(
            W_TECHNIQUE * technique_score
            + W_INFRA * infra_score
            + W_MALWARE * malware_score, 4)

        # Corroboration can raise the band by AT MOST one step, and only with
        # non-empty evidence. Technique overlap remains the floor.
        band = base_band
        if (infra_evidence or malware_evidence):
            band = _bump_band(base_band)

        if not distinctive:
            caveat = (
                "Overlap consists only of techniques common to most profiled "
                "groups; it does not single this group out. Attribution needs "
                "distinctive tooling, infrastructure or family indicators."
            )
        elif band != "HIGH":
            caveat = "Profile partially matches; consider broader collection."
        else:
            caveat = "Strong technique + tactic overlap including distinctive techniques."
        candidates.append({
            "group_id": gid,
            "group_name": info.get("name", ""),
            "aliases": (info.get("aliases") or [])[:5],
            "score": technique_score,          # kept for continuity
            "fused_score": fused_score,
            "components": {
                "technique": technique_score,
                "infra": round(infra_score, 3),
                "malware": round(malware_score, 3),
            },
            "confidence_band": band,
            "technique_band": base_band,
            "band_boosted": band != base_band,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "overlap_count": overlap,
            "matched_techniques": sorted(overlap_set),
            "distinctive_techniques": sorted(distinctive),
            "missing_techniques": sorted(gtids - observed)[:10],
            "total_group_techniques": len(gtids),
            "infra_evidence": infra_evidence,
            "malware_evidence": malware_evidence,
            "caveat": caveat,
        })

    # Sort by fused score. When infra+malware are 0 everywhere, fused_score is a
    # positive multiple of the old F1 score, so the ordering (and tie-breaks) is
    # identical to the pre-fusion ranking.
    candidates.sort(key=lambda c: (-c["fused_score"], -c["overlap_count"], c["group_id"]))
    top = candidates[:top_n]

    suggested_finding = None
    if top and top[0]["confidence_band"] in {"HIGH", "MEDIUM"}:
        primary = top[0]
        tier = "LIKELY" if primary["confidence_band"] == "HIGH" else "SUSPECTED"
        corrob = ""
        if primary["infra_evidence"] or primary["malware_evidence"]:
            bits = primary["infra_evidence"] + primary["malware_evidence"]
            corrob = f"; corroborated by {'; '.join(bits[:3])}"
        suggested_finding = {
            "description": (
                f"Adversary attribution: profile matches "
                f"{primary['group_name']} ({primary['group_id']}) — "
                f"{primary['overlap_count']} overlapping techniques across "
                f"{observed_tactic_count} tactics ({primary['confidence_band']} band)"
                f"{corrob}"
            ),
            "confidence": tier,
            "source": "attribution.attribute_actors",
            "primary_group_id": primary["group_id"],
        }

    return {
        "success": True,
        "observed_tid_count": len(observed),
        "observed_tactic_count": observed_tactic_count,
        "finding_count": finding_count,
        "weights": {"technique": W_TECHNIQUE, "infra": W_INFRA, "malware": W_MALWARE},
        "candidates": top,
        "total_candidates_above_threshold": len(candidates),
        "table_size": len(groups_table),
        "suggested_finding": suggested_finding,
    }
