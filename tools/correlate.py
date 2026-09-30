"""Cross-tool correlation — joins outputs from existing Atlas tools into
structured findings that judges can verify in the audit trail.

These are higher-order analytical tools: they don't run new forensic processes;
they read prior tool_call results from the execution log and merge them.
"""
import json
import os
import re
from typing import Optional
from fastmcp import FastMCP

from tools.mitre import (
    DEFAULT_TECHNIQUES_PATH as DEFAULT_MITRE_PATH,
    load_techniques as _load_mitre_techniques,
)

mcp = FastMCP("correlate")


def _load_mitre(path: Optional[str] = None) -> dict:
    """Thin shim over tools.mitre.load_techniques. Kept as a name so existing
    call sites don't have to change. Returns the full doc including _meta."""
    return _load_mitre_techniques(path)


def _recent_tool_stdouts(tool_substring: str, max_entries: int = 50) -> list[dict]:
    """Return recent tool_call entries whose cmd contains tool_substring.

    Used by correlation tools to look up the actual output the agent collected.
    Returns a list of {call_id, cmd, stdout_excerpt, success} dicts.
    """
    from core.execution_log import log
    matches = []
    for e in reversed(log._entries):
        if e.get("type") != "tool_call":
            continue
        cmd = e.get("cmd", "") or ""
        if tool_substring not in cmd:
            continue
        matches.append({
            "call_id": e.get("call_id"),
            "cmd": cmd,
            "stdout_excerpt": e.get("stdout_excerpt", "") or "",
            "success": e.get("success", False),
        })
        if len(matches) >= max_entries:
            break
    return list(reversed(matches))


# ── Process ↔ File correlation ──────────────────────────────────────────────

_PID_LINE_RE = re.compile(r"\b(?:PID|Pid)[:=]?\s*(\d+)\b")
# Windows path or absolute Linux path with at least 2 segments. The Linux side
# requires a non-empty middle segment so things like "/r" inside "r/r" don't
# match as a path.
_PATH_RE = re.compile(
    r"([A-Z]:\\[^\s\"'<>|]+|/[A-Za-z0-9_.\-]+/[^\s\"'<>|]+)"
)


def _best_path(line: str) -> Optional[str]:
    """Return the longest path-like token in line, or None.

    Prefers full Windows paths (C:\\…) over short Unix-style fragments. Resolves
    regex alternation order bias in lines that contain both "r/r" markers (TSK)
    and Windows paths.
    """
    matches = _PATH_RE.findall(line)
    if not matches:
        return None
    return max(matches, key=len)


@mcp.tool()
def process_to_file(pid: Optional[int] = None, path_substring: Optional[str] = None) -> dict:
    """
    Join vol.psscan/pslist (memory) findings to tsk.fls/MFTECmd (disk) records
    for the same image paths. Useful for confirming that a memory-resident
    process maps to an on-disk artifact (and vice versa).

    pid: optional PID filter — return correlations only for this process.
    path_substring: optional path filter (e.g. "Temp", "System32").

    Returns:
      correlations: list of {pid, process_name, memory_call_id, file_path,
                              disk_call_id, source_excerpts}.
    """
    # Pull recent vol process listings + recent disk listings from the trace.
    vol_entries = _recent_tool_stdouts("vol")
    disk_entries = (
        _recent_tool_stdouts("fls")
        + _recent_tool_stdouts("MFTECmd")
        + _recent_tool_stdouts("mftecmd")
    )

    # Extract (pid, candidate_path) tuples from vol output, keyed to call_ids.
    process_records: list[dict] = []
    for e in vol_entries:
        text = e["stdout_excerpt"]
        for line in text.splitlines():
            if pid is not None and str(pid) not in line:
                continue
            pid_match = _PID_LINE_RE.search(line) or re.search(r"^\s*\*?\s*(\d+)\s", line)
            path = _best_path(line)
            if pid_match and path:
                p = int(pid_match.group(1))
                if pid is not None and p != pid:
                    continue
                process_records.append({
                    "pid": p,
                    "candidate_path": path,
                    "memory_call_id": e["call_id"],
                    "memory_excerpt": line.strip()[:200],
                })

    # Build a path → disk_call_id index from disk_entries.
    disk_index: dict[str, dict] = {}
    for e in disk_entries:
        for line in e["stdout_excerpt"].splitlines():
            path = _best_path(line)
            if not path:
                continue
            disk_index.setdefault(path.lower(), {
                "disk_call_id": e["call_id"],
                "disk_excerpt": line.strip()[:200],
            })

    correlations = []
    for proc in process_records:
        cand = proc["candidate_path"]
        if path_substring and path_substring.lower() not in cand.lower():
            continue
        disk = disk_index.get(cand.lower())
        if not disk:
            # Try basename match as fallback
            basename = cand.replace("\\", "/").split("/")[-1].lower()
            for k, v in disk_index.items():
                if k.endswith("/" + basename) or k.endswith("\\" + basename):
                    disk = v
                    break
        if disk:
            correlations.append({
                "pid": proc["pid"],
                "candidate_path": cand,
                "memory_call_id": proc["memory_call_id"],
                "disk_call_id": disk["disk_call_id"],
                "memory_excerpt": proc["memory_excerpt"],
                "disk_excerpt": disk["disk_excerpt"],
            })

    return {
        "success": True,
        "correlations": correlations,
        "process_records_examined": len(process_records),
        "disk_paths_indexed": len(disk_index),
    }


# ── Network ↔ Process correlation ───────────────────────────────────────────

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PORT_RE = re.compile(r":(\d{1,5})\b")


@mcp.tool()
def network_to_process(ip: Optional[str] = None, port: Optional[int] = None) -> dict:
    """
    Join vol.netscan/netstat connections to vol.pslist/psscan process names
    for the same PID. Surfaces which process owned each suspicious connection.

    ip: optional IP filter (substring match).
    port: optional port filter (exact match).

    Returns:
      connections: list of {pid, process_name, local_endpoint, remote_endpoint,
                            netscan_call_id, pslist_call_id, excerpt}.
    """
    netscan_entries = _recent_tool_stdouts("netscan") + _recent_tool_stdouts("netstat")
    process_entries = _recent_tool_stdouts("pslist") + _recent_tool_stdouts("psscan")

    # Build pid → process_name from process listings.
    pid_to_name: dict[int, dict] = {}
    for e in process_entries:
        for line in e["stdout_excerpt"].splitlines():
            m = re.match(r"\s*\*?\s*(\d+)\s+(\S+)", line)
            if m:
                p = int(m.group(1))
                pid_to_name.setdefault(p, {
                    "name": m.group(2),
                    "pslist_call_id": e["call_id"],
                })

    connections = []
    for e in netscan_entries:
        for line in e["stdout_excerpt"].splitlines():
            ips = _IPV4_RE.findall(line)
            ports = [int(p) for p in _PORT_RE.findall(line)]
            pid_match = re.search(r"\b(\d{2,5})\s+(?:\S+\.exe|\S+)$", line)
            if ip and not any(ip in i for i in ips):
                continue
            if port and port not in ports:
                continue
            if not ips:
                continue
            line_pid = None
            for token in line.split():
                if token.isdigit():
                    v = int(token)
                    if 4 <= v <= 65535 and (pid_match is None or v == int(pid_match.group(1))):
                        line_pid = v
                        break
            proc_info = pid_to_name.get(line_pid or -1, {})
            connections.append({
                "pid": line_pid,
                "process_name": proc_info.get("name", ""),
                "ips": ips,
                "ports": ports,
                "netscan_call_id": e["call_id"],
                "pslist_call_id": proc_info.get("pslist_call_id"),
                "excerpt": line.strip()[:200],
            })

    return {
        "success": True,
        "connections": connections,
        "pids_indexed": len(pid_to_name),
    }


# ── Finding ↔ MITRE ATT&CK mapping ──────────────────────────────────────────

@mcp.tool()
def mitre_map(finding_text: str, top_n: int = 5,
              table_path: Optional[str] = None) -> dict:
    """
    Map a finding to candidate MITRE ATT&CK technique IDs by keyword score.

    finding_text: the finding description (or any investigative text).
    top_n: number of candidates to return.
    table_path: override the default ATT&CK reference path.

    Returns:
      candidates: list of {technique_id, name, tactic, score, matched_keywords}.
                  Sorted by score descending.
    """
    table = _load_mitre(table_path or DEFAULT_MITRE_PATH)
    techniques = table.get("techniques", {})
    if not techniques:
        return {"success": False, "error":
                f"MITRE table not found or empty: {table_path or DEFAULT_MITRE_PATH}"}

    text_lower = finding_text.lower()
    scored: list[dict] = []
    for tid, info in techniques.items():
        keywords = info.get("keywords", []) or []
        matched = []
        for k in keywords:
            kl = k.lower()
            # Word-boundary match so "tor" doesn't match inside "doctor" or
            # "notarealthreat". For multi-word phrases (e.g. "scheduled task"),
            # fall back to substring match since \b doesn't work mid-phrase.
            if " " in kl:
                if kl in text_lower:
                    matched.append(k)
            else:
                if re.search(rf"\b{re.escape(kl)}\b", text_lower):
                    matched.append(k)
        if not matched:
            continue
        scored.append({
            "technique_id": tid,
            "name": info.get("name", ""),
            "tactic": info.get("tactic", ""),
            "score": round(len(matched) / max(len(keywords), 1), 3),
            "matched_keywords": matched,
            "dfir_relevant": bool(info.get("dfir_relevant", True)),
        })
        # Pre-compromise techniques (reconnaissance, resource development) are
        # suggested only when nothing observable from the evidence matched.
        if any(x["dfir_relevant"] for x in scored):
            scored = [x for x in scored if x["dfir_relevant"]]

    scored.sort(key=lambda x: (-x["score"], -len(x["matched_keywords"]), x["technique_id"]))
    return {
        "success": True,
        "candidates": scored[:top_n],
        "techniques_examined": len(techniques),
    }


@mcp.tool()
def mitre_validate(technique_id: str, table_path: Optional[str] = None) -> dict:
    """
    Verify an ATT&CK technique ID exists in the reference table.

    Returns: {exists: bool, name, tactic, description} or {exists: False}.
    Use before writing a technique ID into a report.
    """
    table = _load_mitre(table_path or DEFAULT_MITRE_PATH)
    techniques = table.get("techniques", {})
    info = techniques.get(technique_id)
    if info:
        out = {
            "success": True,
            "exists": True,
            "technique_id": technique_id,
            "name": info.get("name", ""),
            "tactic": info.get("tactic", ""),
            "description": info.get("description", ""),
        }
        # Revoked/deprecated IDs are real and citable, but flag the current
        # replacement so reports can cite the up-to-date ID.
        if info.get("status"):
            out["status"] = info["status"]
            if info.get("superseded_by"):
                out["superseded_by"] = info["superseded_by"]
                out["note"] = (
                    f"{technique_id} was {info['status']} by ATT&CK; "
                    f"current equivalent is {info['superseded_by']}."
                )
        return out
    return {
        "success": True,
        "exists": False,
        "technique_id": technique_id,
        "available_count": len(techniques),
    }


# ── Kill-chain timeline / dependency chain ──────────────────────────────────
#
# Orders the investigation's recorded findings along the attack kill chain and
# ties each one back to the tool call that produced it — an
# evidence → tool → finding → attack-stage dependency chain. The MITRE ATT&CK
# tactic sequence IS the fine-grained kill chain; each tactic also rolls up to a
# coarse Lockheed-Martin phase for a one-glance narrative.

# Canonical ATT&CK Enterprise tactic order (the fine-grained kill chain).
# `stealth` / `defense impairment` are the ATT&CK v19 split of the old
# `defense evasion` tactic; all three are kept so pre-v19 tables still order.
_MITRE_TACTIC_ORDER = [
    "reconnaissance", "resource development", "initial access", "execution",
    "persistence", "privilege escalation", "defense evasion", "stealth",
    "defense impairment",
    "credential access", "discovery", "lateral movement", "collection",
    "command and control", "exfiltration", "impact",
]
_TACTIC_INDEX = {t: i for i, t in enumerate(_MITRE_TACTIC_ORDER)}

# ATT&CK tactic → coarse Lockheed-Martin kill-chain phase.
_TACTIC_TO_KILLCHAIN = {
    "reconnaissance": "Reconnaissance",
    "resource development": "Weaponization",
    "initial access": "Delivery",
    "execution": "Exploitation",
    "persistence": "Installation",
    "privilege escalation": "Installation",
    "defense evasion": "Installation",
    "stealth": "Installation",
    "defense impairment": "Installation",
    "credential access": "Actions on Objectives",
    "discovery": "Actions on Objectives",
    "lateral movement": "Actions on Objectives",
    "collection": "Actions on Objectives",
    "command and control": "Command & Control",
    "exfiltration": "Actions on Objectives",
    "impact": "Actions on Objectives",
}
_UNMAPPED_ORDER = len(_MITRE_TACTIC_ORDER)  # sorts after every known tactic


def _norm_tactic(tactic: str) -> str:
    """Normalise a tactic label to the lowercase, space-separated key used in
    the order/kill-chain tables (ATT&CK exports vary: hyphens, title case)."""
    return (tactic or "").strip().lower().replace("-", " ").replace("_", " ")


def _tool_call_by_id(call_id: int) -> Optional[dict]:
    """The tool_call trace entry with this call_id, if any (for lineage)."""
    if not call_id:
        return None
    from core.execution_log import log
    for e in log._entries:
        if e.get("call_id") == call_id and e.get("type") == "tool_call":
            return e
    return None


def _finding_techniques(entry: dict, infer_unlabeled: bool,
                        table_path: Optional[str]) -> list[dict]:
    """Techniques (with tactic) attached to a finding. Prefers the gate-
    validated techniques stamped on the entry; otherwise, when infer_unlabeled,
    keyword-maps the description to a best-guess technique (flagged inferred)."""
    validated = entry.get("validated_techniques") or []
    out: list[dict] = []
    for t in validated:
        if isinstance(t, dict) and t.get("technique_id"):
            out.append({"technique_id": t.get("technique_id"),
                        "name": t.get("name", ""),
                        "tactic": t.get("tactic", ""),
                        "inferred": False})
    if out or not infer_unlabeled:
        return out
    guess = mitre_map(entry.get("description", "") or "", top_n=1,
                      table_path=table_path)
    for c in (guess.get("candidates") or [])[:1]:
        out.append({"technique_id": c.get("technique_id"),
                    "name": c.get("name", ""),
                    "tactic": c.get("tactic", ""),
                    "inferred": True})
    return out


@mcp.tool()
def killchain_timeline(table_path: Optional[str] = None,
                       infer_unlabeled: bool = True) -> dict:
    """
    Order the investigation's recorded findings along the attack kill chain.

    Reads every `finding` entry from the execution log, maps each to its MITRE
    ATT&CK technique/tactic (preferring the gate-validated techniques already
    stamped on the finding; otherwise keyword-inferring one when
    infer_unlabeled), and arranges them along the ATT&CK tactic sequence — which
    also rolls up to coarse Lockheed-Martin kill-chain phases. Each finding is
    tied back to the tool call that produced it (linked_call_id), yielding an
    evidence → tool → finding → attack-stage dependency chain.

    table_path: override the default ATT&CK reference path.
    infer_unlabeled: keyword-map findings that carry no validated technique.

    Returns:
      stages: kill-chain-ordered list of {tactic, killchain_phase, order,
              findings:[...]}; each finding row carries ts, confidence,
              technique, and its source_tool/source_call_id lineage.
      timeline: findings flattened, sorted by (tactic order, timestamp).
      per_host: timeline rows bucketed by the findings' host tag (multi-host
              cases; untagged findings land in "unattributed"). Only present
              when at least one finding carries host= — this is the data
              source for the estate report's per-host disposition table.
      unmapped: findings with no technique (need MITRE tagging).
      stats: counts.
    """
    from core.claim_graph import asserted_finding_entries
    from core.execution_log import log
    findings = asserted_finding_entries(
        [e for e in log._entries if e.get("type") == "finding"], log.case_dir())

    # Bucket rows per tactic; keep unmapped findings aside.
    per_tactic: dict[str, list[dict]] = {}
    flat: list[dict] = []
    unmapped: list[dict] = []

    for f in findings:
        techniques = _finding_techniques(f, infer_unlabeled, table_path)
        src = _tool_call_by_id(f.get("linked_call_id", 0))
        source_tool = ""
        if src and src.get("cmd"):
            source_tool = src["cmd"].split()[0] if src["cmd"].split() else ""
        base = {
            "call_id": f.get("call_id"),
            "ts": f.get("ts", ""),
            "description": f.get("description", ""),
            "confidence": f.get("confidence", ""),
            "linked_call_id": f.get("linked_call_id", 0),
            "source_call_id": src.get("call_id") if src else 0,
            "source_tool": source_tool,
        }
        if f.get("host"):
            base["host"] = f["host"]
        if not techniques:
            unmapped.append(base)
            continue
        # Rank the finding's tactics; its "primary" (earliest kill-chain) tactic
        # drives its position in the flat timeline.
        ordered = sorted(
            techniques,
            key=lambda t: _TACTIC_INDEX.get(_norm_tactic(t["tactic"]),
                                            _UNMAPPED_ORDER))
        primary = ordered[0]
        p_norm = _norm_tactic(primary["tactic"])
        flat.append({
            **base,
            "technique_id": primary["technique_id"],
            "technique_name": primary["name"],
            "tactic": p_norm,
            "killchain_phase": _TACTIC_TO_KILLCHAIN.get(p_norm, "Unmapped"),
            "inferred": primary["inferred"],
            "order": _TACTIC_INDEX.get(p_norm, _UNMAPPED_ORDER),
        })
        for t in techniques:
            norm = _norm_tactic(t["tactic"])
            per_tactic.setdefault(norm, []).append({
                **base,
                "technique_id": t["technique_id"],
                "technique_name": t["name"],
                "inferred": t["inferred"],
            })

    # Stages, ordered along the kill chain; unknown tactics sort last.
    stages = []
    for norm in sorted(per_tactic, key=lambda n: _TACTIC_INDEX.get(
            n, _UNMAPPED_ORDER)):
        rows = sorted(per_tactic[norm], key=lambda r: r.get("ts", ""))
        stages.append({
            "tactic": norm,
            "killchain_phase": _TACTIC_TO_KILLCHAIN.get(norm, "Unmapped"),
            "order": _TACTIC_INDEX.get(norm, _UNMAPPED_ORDER),
            "findings": rows,
        })

    flat.sort(key=lambda r: (r["order"], r.get("ts", "")))
    out = {
        "success": True,
        "stages": stages,
        "timeline": flat,
        "unmapped": unmapped,
        "stats": {
            "findings_total": len(findings),
            "findings_mapped": len(flat),
            "findings_unmapped": len(unmapped),
            "stages": len(stages),
        },
    }
    # Multi-host cases: bucket the kill-chain rows per host so the estate
    # report's per-host disposition table falls out of the trace instead of
    # being hand-assembled from prose. Untagged rows (including unmapped
    # findings) go to "unattributed" so nothing silently drops out.
    if any(f.get("host") for f in findings):
        per_host: dict[str, list[dict]] = {}
        for row in flat:
            per_host.setdefault(row.get("host") or "unattributed",
                                []).append(row)
        for row in unmapped:
            per_host.setdefault(row.get("host") or "unattributed",
                                []).append(row)
        out["per_host"] = {
            h: sorted(rows, key=lambda r: (r.get("order", _UNMAPPED_ORDER),
                                           r.get("ts", "")))
            for h, rows in sorted(per_host.items())
        }
        out["stats"]["hosts"] = len(out["per_host"])
    return out


# ── Cross-source evidence reconciliation ─────────────────────────────────────

@mcp.tool()
def cross_source_reconciliation(
    profiles: Optional[list[str]] = None,
    focus_ips: Optional[list[str]] = None,
    case_dir: Optional[str] = None,
) -> dict:
    """
    Reconcile forensic events across SIEM exports, disk event-log CSVs, and
    investigation timelines. Surfaces coverage gaps (e.g. SIEM-only logons),
    earliest-event mismatches per source family, and blocking issues before
    report finalization.

    profiles: reconciliation categories to run (default: all from manifest —
              successful_logon, failed_logon, process_creation, network_connection).
    focus_ips: external IPs to scope reconciliation (default: auto-detect from
               Wazuh bundles and records).
    case_dir: override case directory (default: active case from execution log).

    Writes analysis/cross_source_reconciliation.json and .md.
    """
    from core.cross_source_reconciliation import run_reconciliation

    if case_dir is None:
        try:
            from core.execution_log import log
            case_dir = log.case_dir()
        except Exception:
            case_dir = None
    if not case_dir:
        return {"success": False, "error": "no active case directory"}

    return run_reconciliation(
        case_dir,
        profiles=profiles,
        focus_ips=focus_ips,
        write_outputs=True,
    )
