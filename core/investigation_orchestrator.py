"""Investigation Resource Manager / Orchestrator — planning compose layer.

The Orchestrator does **not** replace Plane A, DAIR, or middleware. It gathers
investigation resources and scores candidate actions so the Investigation Plan
optimises the *investigation*, not token usage alone.

Resources (inputs):
  - investigation tasks / claims / findings / evidence catalog
  - context budget (``core.context_budget``)
  - tool capability manifest (``tools.tool_capabilities``)
  - input-scale cost estimates (``core.input_scale``)
  - prior parse artifacts / coverage hints (``core.coverage``)

Outputs feed ``investigation_plan.candidates`` and a ``resources`` snapshot.
Ranking is deterministic metadata scoring (no hardcoded decision trees).
When top scores are flat, an optional LLM refine may reorder *only among
the existing candidate list* (Phase 4). Continuous stewardship (Phase 3)
re-runs via ``refresh_orchestration`` each agent turn / after claim updates.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Optional

from core.envfile import env_float, env_int

# Soft keyword → capability id boosts (investigation themes, not trees).
_THEME_CAPABILITY: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("rdp", "remote desktop", "terminal services", "nla"),
     ("windows_event_logs", "tabular_export_analysis")),
    (("bitlocker", "tpm", "fve", "encryption"),
     ("windows_event_logs", "windows_registry_identity")),
    (("usb", "removable", "thumb drive", "pnp"),
     ("windows_event_logs", "disk_filesystem_timeline")),
    (("powershell", "script block", "encodedcommand"),
     ("windows_event_logs", "deobfuscation", "tabular_export_analysis")),
    (("lateral", "psexec", "wmi", "smb", "pass-the-hash", "pth", "auth"),
     ("windows_event_logs", "cross_artifact_correlation")),
    (("persist", "persistence", "run key", "scheduled task", "service"),
     ("windows_registry_identity", "disk_filesystem_timeline", "live_endpoint")),
    (("memory", "ram", "dump", "malware process"),
     ("memory_process_network", "ioc_scan_enrichment")),
    (("pcap", "network capture", "dns", "http traffic"),
     ("network_pcap", "ioc_scan_enrichment")),
    (("email", "phishing", "pst", "msg"),
     ("email_forensics", "static_file_triage")),
)

_EXT_CAPABILITY: dict[str, tuple[str, ...]] = {
    ".evtx": ("windows_event_logs", "tabular_export_analysis"),
    ".csv": ("tabular_export_analysis",),
    ".tsv": ("tabular_export_analysis",),
    ".jsonl": ("tabular_export_analysis",),
    ".xlsx": ("tabular_export_analysis",),
    ".pcap": ("network_pcap",),
    ".pcapng": ("network_pcap",),
    ".e01": ("disk_filesystem_timeline",),
    ".ex01": ("disk_filesystem_timeline",),
    ".vmdk": ("disk_filesystem_timeline",),
    ".raw": ("disk_filesystem_timeline",),
    ".dd": ("disk_filesystem_timeline",),
    ".mem": ("memory_process_network",),
    ".dmp": ("memory_process_network",),
    ".vmem": ("memory_process_network",),
    ".mft": ("disk_filesystem_timeline",),
    ".hive": ("windows_registry_identity",),
    ".dat": ("windows_registry_identity", "static_file_triage"),
    ".pf": ("disk_filesystem_timeline",),
    ".lnk": ("disk_filesystem_timeline",),
    ".job": ("disk_filesystem_timeline", "windows_registry_identity"),
    ".xml": ("disk_filesystem_timeline", "static_file_triage"),
}

# Preferred first tool per capability (planning vocabulary, not a decision tree).
_CAP_PRIMARY_TOOL: dict[str, str] = {
    "windows_event_logs": "ez.evtxecmd",
    "tabular_export_analysis": "table.table_query",
    "disk_filesystem_timeline": "ez.mftecmd",
    "windows_registry_identity": "misc.regripper_hive",
    "memory_process_network": "vol.pslist",
    "network_pcap": "net.tcpdump_list_connections",
    "static_file_triage": "strings.file_identify",
    "deobfuscation": "deob.decode_chain",
    "ioc_scan_enrichment": "yara.scan_file",
    "live_endpoint": "live.live_persistence_audit",
    "email_forensics": "misc.parse_email",
    "cross_artifact_correlation": "correlate.killchain_timeline",
}

_COST_CLASS = {
    "artifact_only": "high",
    "summary": "medium",
    "filtered": "medium",
    "full": "low",
    "reference_only": "low",
}


def gather_resources(
    case_dir: str | os.PathLike,
    *,
    plane_a_result: Optional[dict[str, Any]] = None,
    ordered_tasks: Optional[list[dict[str, Any]]] = None,
    focus_hosts: Optional[list[str]] = None,
    revisit_claim_ids: Optional[list[str]] = None,
    context_budget: Optional[dict[str, Any]] = None,
    messages: Optional[list] = None,
    model: str = "",
    provider: str = "",
) -> dict[str, Any]:
    """Snapshot all planning inputs for the orchestrator / plan brief."""
    root = Path(case_dir).resolve()
    plane = plane_a_result or {}
    tasks = ordered_tasks or []
    hosts = focus_hosts or []
    revisit = revisit_claim_ids or []

    budget: dict[str, Any] = {}
    try:
        from core import context_budget as _cb
        if context_budget:
            budget = context_budget
        elif messages is not None:
            budget = _cb.compute(
                root, persist=True, messages=messages,
                model=model, provider=provider)
        else:
            loaded = _cb.load_budget(root)
            if loaded.get("conversation_included"):
                budget = loaded
            else:
                budget = _cb.compute(
                    root, persist=True, model=model, provider=provider)
    except Exception:
        budget = {}

    catalog_units = 0
    try:
        from core.evidence_catalog import load_catalog
        catalog_units = len(load_catalog(root).get("units") or {})
    except Exception:
        pass

    findings_n = 0
    try:
        from core.finding_index import load_index
        findings_n = len((load_index(root) or {}).get("by_f_id") or {})
    except Exception:
        try:
            fdir = root / "findings"
            if fdir.is_dir():
                findings_n = sum(1 for _ in fdir.glob("*.md"))
        except Exception:
            pass

    claims_n = 0
    try:
        import json
        cg = root / ".atlas" / "claim_graph.json"
        if cg.is_file():
            data = json.loads(cg.read_text(encoding="utf-8"))
            claims_n = len(data.get("nodes") or [])
    except Exception:
        pass

    caps_version = ""
    try:
        from tools.tool_capabilities import tool_capability_manifest
        caps_version = tool_capability_manifest().get("version") or ""
    except Exception:
        pass

    focus_blob = " ".join((t.get("text") or "") for t in tasks) + " " + " ".join(hosts)

    return {
        "orchestrator": "investigation_resource_manager",
        "schema_hint": "1.2",
        "open_task_count": len(tasks),
        "revisit_claim_count": len(revisit),
        "open_conflict_count": len(plane.get("open_conflicts") or []),
        "catalog_unit_count": catalog_units,
        "claim_node_count": claims_n,
        "finding_count": findings_n,
        "context_budget": {
            k: budget.get(k)
            for k in (
                "window_tokens",
                "available_for_tool_output_tokens",
                "available_for_evidence_tokens",
                "detail_policy",
                "max_bulk_dir_files",
                "model",
                "provider",
                "disk_first",
                "conversation_included",
                "conversation_tokens",
            )
        },
        "tool_manifest_version": caps_version,
        "focus_text_preview": focus_blob[:240],
        "note": (
            "Context budget is one resource. Rank actions by investigation "
            "value × tool fit × budget fit × inverse cost."
        ),
    }


def _theme_capability_boosts(focus_text: str) -> dict[str, float]:
    text = (focus_text or "").casefold()
    boosts: dict[str, float] = {}
    if not text:
        return boosts
    for keywords, caps in _THEME_CAPABILITY:
        if any(k in text for k in keywords):
            for c in caps:
                boosts[c] = boosts.get(c, 0.0) + 4.0
    return boosts


# Already-parsed tool exports: readable text/tabular output, never a raw
# artifact for a path parser. "SECURITY.regripper.txt → misc.regripper_hive"
# would sit as the static top orchestrator hint for a whole run, because
# the hive-name heuristic below matched the *export's* basename.
_PREPARSED_SUFFIXES = (
    ".regripper.txt", ".csv", ".tsv", ".json", ".jsonl", ".txt", ".xlsx",
)


def _path_capabilities(path: str) -> list[str]:
    p = Path(path)
    name = p.name.casefold()
    ext = p.suffix.lower()
    caps: list[str] = []
    if ext in _EXT_CAPABILITY:
        caps.extend(_EXT_CAPABILITY[ext])
    preparsed = name.endswith(_PREPARSED_SUFFIXES)
    if not caps and not preparsed:
        # A firewall/IIS/Zeek export called ".log" is a table; the plan
        # kept sending it to strings.file_identify.
        try:
            from core.input_kind import looks_delimited
            preparsed = looks_delimited(path)
        except Exception:  # noqa: BLE001
            preparsed = False
    if preparsed and "tabular_export_analysis" not in caps:
        # .txt / .regripper.txt have no _EXT_CAPABILITY entry — route them to
        # table.* (grep/query) instead of falling through to hive heuristics.
        caps.insert(0, "tabular_export_analysis")
    # Registry hives often lack .hive — but a parsed export is never a hive.
    if (not preparsed
            and any(x in name for x in
                    ("ntuser", "sam", "system", "software", "security"))
            and not name.endswith(".evtx")):
        if "windows_registry_identity" not in caps:
            caps.append("windows_registry_identity")
    if name.endswith(".csv") or "/analysis/" in path.replace("\\", "/").casefold():
        if "tabular_export_analysis" not in caps:
            caps.insert(0, "tabular_export_analysis")
    # Prefer table.* when artifact already parsed
    if ext in {".csv", ".tsv", ".jsonl"} and "tabular_export_analysis" in caps:
        caps = ["tabular_export_analysis"] + [c for c in caps if c != "tabular_export_analysis"]
    # static_file_triage / strings.file_identify is last resort only — never
    # the sole top capability for unknown junk under tool trees.
    if not caps:
        try:
            from core.coverage_ledger import is_noise_path
            if is_noise_path(path):
                return []  # unscorable noise
        except Exception:
            pass
        return ["static_file_triage"]
    return caps


def suggest_tools_for_path(
    path: str,
    *,
    focus_text: str = "",
    limit: int = 3,
) -> list[dict[str, Any]]:
    """Rank capability/tools for a path given investigation focus text."""
    try:
        from tools.tool_capabilities import tool_capability_manifest
        caps = {
            c["id"]: c
            for c in (tool_capability_manifest().get("capabilities") or [])
            if isinstance(c, dict) and c.get("id")
        }
    except Exception:
        caps = {}

    theme = _theme_capability_boosts(focus_text)
    path_caps = _path_capabilities(path)
    scored: list[dict[str, Any]] = []
    for cid in path_caps:
        cap = caps.get(cid) or {"id": cid, "tools": [], "purpose": ""}
        tools = list(cap.get("tools") or [])
        if not tools and cid not in caps:
            continue
        primary = _CAP_PRIMARY_TOOL.get(cid) or (tools[0] if tools else "")
        if cid == "disk_filesystem_timeline":
            # Prefer chain-info on VMDK; tsk.mmls on already-flattened raw.
            try:
                from core.runtime_capabilities import disk_open_tool_for_path
                primary = disk_open_tool_for_path(path)
            except Exception:
                if path.lower().endswith(".vmdk"):
                    primary = "img.vmdk_chain_info"
                elif path.lower().endswith((".raw", ".dd", ".img")):
                    primary = "tsk.mmls"
        score = 2.0 + float(theme.get(cid, 0.0))
        # Prefer tabular query when CSV already on disk
        if cid == "tabular_export_analysis" and path.lower().endswith((".csv", ".tsv")):
            score += 6.0
        scored.append({
            "capability_id": cid,
            "tool_hint": primary,
            "alt_tools": [t for t in tools[:5] if t != primary],
            "purpose": (cap.get("purpose") or "")[:160],
            "tool_fit": round(score, 2),
        })
    scored.sort(key=lambda x: -float(x.get("tool_fit") or 0))
    return scored[:limit]


def score_candidate(
    *,
    path: str,
    affinity: float,
    est_tokens: int,
    detail_level: str,
    tool_room: int,
    focus_text: str = "",
    case_dir: str | os.PathLike | None = None,
) -> dict[str, Any]:
    """Combine investigation value, tool fit, budget fit, and cost class."""
    try:
        from core.coverage_ledger import is_noise_path
        if is_noise_path(path):
            return {
                "path": path,
                "tool_hint": "",
                "capability_id": "",
                "alt_tools": [],
                "purpose": "noise path excluded",
                "affinity": float(affinity),
                "tool_fit": 0.0,
                "budget_fit": 0.0,
                "cost_class": "high",
                "score": 0.0,
                "filtered": True,
                "filter_reason": "noise_path",
            }
    except Exception:
        pass
    tools = suggest_tools_for_path(path, focus_text=focus_text, limit=2)
    best = tools[0] if tools else {
        "capability_id": "",
        "tool_hint": "",
        "tool_fit": 0.0,
        "alt_tools": [],
        "purpose": "",
    }
    # Demote strings.file_identify / static_file_triage — never outrank tabular
    tool_hint = str(best.get("tool_hint") or "")
    tool_fit = float(best.get("tool_fit") or 0)
    if (best.get("capability_id") == "static_file_triage"
            or tool_hint.endswith("file_identify")):
        tool_fit = min(tool_fit, 1.0)
    # Investigation value: affinity + tool_fit (theme-aware)
    inv_value = float(affinity) + tool_fit * 0.5
    # Budget fit: 1.0 when artifact_only/disk-first still viable; collapses only
    # when we would have refused entirely (we don't for single files).
    if tool_room <= 0:
        budget_fit = 0.35
    elif est_tokens <= tool_room:
        budget_fit = 1.0
    elif detail_level == "artifact_only":
        budget_fit = 0.75  # disk-first still useful
    else:
        budget_fit = max(0.2, tool_room / max(est_tokens, 1))
    cost_class = _COST_CLASS.get(detail_level, "medium")
    cost_penalty = {"low": 1.0, "medium": 0.85, "high": 0.7}.get(cost_class, 0.8)
    # Boost tables near the top of the evidence tree and parser exports
    # (a parser's output folder): the delivery's own tree names are never
    # assumed.
    from core.path_hints import PARSER_DIR_RE
    low = path.replace("\\", "/").casefold()
    if low.endswith((".csv", ".tsv", ".xlsx")) and (
            low.count("/") <= 2 or PARSER_DIR_RE.search(low)):
        inv_value += 4.0
    # CASE.md Evidence Links — declared host/path map outranks affinity noise
    if case_dir is not None:
        try:
            from core.evidence_links import path_link_boost
            inv_value += path_link_boost(path, case_dir)
        except Exception:
            pass
        # Soft coverage / task debt (B4/B5): pull unseen HV + open-task paths;
        # lightly demote already-probed sticky re-touches.
        try:
            from core.coverage_ledger import load_ledger
            from core.investigation_tasks import actionable_tasks, link_tokens
            norm = low.lstrip("./")
            for u in (load_ledger(case_dir).get("units") or {}).values():
                if not isinstance(u, dict):
                    continue
                up = str(u.get("path") or "").replace("\\", "/").casefold()
                if up != norm and not norm.endswith("/" + up) and up not in norm:
                    continue
                st = str(u.get("status") or "unseen")
                if st == "unseen":
                    inv_value += 3.0
                elif st == "probed":
                    inv_value -= 1.25
                break
            path_toks = link_tokens(path)
            for t in actionable_tasks(case_dir):
                if path_toks & link_tokens(str(t.get("text") or "")):
                    inv_value += 2.5
                    break
            # Soft disk/tabular mix (B6): after Access has opened media, do not
            # let disk FS tools starve remaining unseen tabular/HV units.
            try:
                from core.evidence_access import media_blocks_degraded_exit
                diskish_hint = any(
                    x in tool_hint.casefold()
                    for x in ("tsk.", "sigfind", "icat", "fls", "indx", "mmls")
                ) or any(
                    x in low for x in (".raw", ".dd", ".e01", ".vmdk")
                )
                if diskish_hint and not media_blocks_degraded_exit(case_dir):
                    unseen_tab = 0
                    for u in (load_ledger(case_dir).get("units") or {}).values():
                        if not isinstance(u, dict):
                            continue
                        if str(u.get("status") or "") != "unseen":
                            continue
                        up = str(u.get("path") or "").casefold()
                        if up.endswith((".csv", ".tsv", ".xlsx", ".jsonl", ".evtx")):
                            unseen_tab += 1
                    if unseen_tab:
                        inv_value -= min(3.0, 1.0 + 0.5 * unseen_tab)
            except Exception:
                pass
        except Exception:
            pass
    score = inv_value * budget_fit * cost_penalty
    return {
        "path": path,
        "tool_hint": tool_hint,
        "capability_id": best.get("capability_id") or "",
        "alt_tools": best.get("alt_tools") or [],
        "affinity": round(float(affinity), 2),
        "est_tokens": int(est_tokens),
        "detail_level": detail_level,
        "investigation_value": round(inv_value, 2),
        "budget_fit": round(budget_fit, 2),
        "cost_class": cost_class,
        "score": round(score, 2),
        "status": "ready",
        "tool_options": tools,
    }


def rank_actions(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort candidate actions by composite score (desc)."""
    return sorted(
        candidates,
        key=lambda c: (
            0 if c.get("status") == "ready" else 1,
            -float(c.get("score") or 0),
            -float(c.get("investigation_value") or 0),
            int(c.get("est_tokens") or 0),
        ),
    )


def format_resources_for_brief(resources: dict[str, Any]) -> str:
    """Short markdown block for the Rerun Brief."""
    lines = [
        "### Investigation resources",
        "",
        f"- Open tasks: {resources.get('open_task_count', 0)}; "
        f"revisit claims: {resources.get('revisit_claim_count', 0)}; "
        f"catalog units: {resources.get('catalog_unit_count', 0)}",
        f"- Claims/findings ≈ {resources.get('claim_node_count', 0)} / "
        f"{resources.get('finding_count', 0)}",
    ]
    ver = resources.get("tool_manifest_version") or ""
    if ver:
        lines.append(f"- Tool capability manifest: {ver}")
    note = resources.get("note") or ""
    if note:
        lines.append(f"- {note}")
    rank = resources.get("ranking_source") or ""
    if rank:
        lines.append(f"- Ranking source: {rank}")
    lines.append("")
    return "\n".join(lines)


# ── Phase 3: continuous stewardship ─────────────────────────────────────

def _dirty_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "orchestrator.dirty"


def _llm_meta_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "orchestrator_llm_rank.json"


def mark_state_dirty(case_dir: str | os.PathLike, reason: str = "") -> None:
    """Signal that claims/tasks changed — next refresh should rebuild."""
    try:
        p = _dirty_path(case_dir)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps({"reason": reason or "state_change", "ts": time.time()}),
            encoding="utf-8",
        )
    except OSError:
        pass


def clear_state_dirty(case_dir: str | os.PathLike) -> None:
    try:
        p = _dirty_path(case_dir)
        if p.is_file():
            p.unlink()
    except OSError:
        pass


def is_state_dirty(case_dir: str | os.PathLike) -> bool:
    return _dirty_path(case_dir).is_file()


def live_strip_summary(plan: dict[str, Any] | None) -> dict[str, Any]:
    """Compact fields for the LIVE UI status strip."""
    plan = plan or {}
    budget = plan.get("context_budget") or {}
    cands = [
        c for c in (plan.get("candidates") or [])
        if c.get("status") == "ready"
    ]
    top = cands[0] if cands else {}
    path = str(top.get("path") or "")
    short = Path(path).name if path else ""
    return {
        "ctx_policy": budget.get("detail_policy") or "",
        "ctx_tool_tok": budget.get("available_for_tool_output_tokens"),
        "orch_score": top.get("score"),
        "orch_tool": top.get("tool_hint") or "",
        "orch_top": short,
        "orch_rank": (plan.get("resources") or {}).get("ranking_source")
        or "deterministic",
        "orch_cands": len(cands),
    }


def refresh_orchestration(
    case_dir: str | os.PathLike,
    *,
    plane_a_result: Optional[dict[str, Any]] = None,
    messages: Optional[list] = None,
    model: str = "",
    provider: str = "",
    llm_client: Any = None,
    turn: int = 0,
    persist: bool = True,
) -> dict[str, Any]:
    """Rebuild investigation plan + budget; optionally LLM-refine flat ranks.

    Called each agent turn (stewardship) and after claim/task dirty signals.
    Fail-open: returns whatever plan could be built.
    """
    from core import context_budget as _cb
    from core.investigation_plan import build_investigation_plan, save_plan

    root = Path(case_dir).resolve()
    dirty = is_state_dirty(root)

    # Always refresh budget with live conversation mass when available.
    snap = None
    try:
        snap = _cb.compute(
            root,
            model=model or "",
            provider=provider or "",
            messages=messages,
            persist=True,
        )
    except Exception:
        snap = None

    plan = build_investigation_plan(
        root,
        plane_a_result=plane_a_result,
        persist=False,
        context_budget=snap,
        messages=messages,
        model=model or "",
        provider=provider or "",
    )
    resources = dict(plan.get("resources") or {})
    resources["ranking_source"] = "deterministic"
    resources["dirty_rebuild"] = dirty
    resources["stewardship_turn"] = turn
    plan["resources"] = resources

    llm_applied = False
    try:
        plan, llm_applied = maybe_llm_refine_ranking(
            plan,
            case_dir=root,
            llm_client=llm_client,
            turn=turn,
        )
    except Exception:
        llm_applied = False

    if persist:
        save_plan(root, plan)
    clear_state_dirty(root)

    strip = live_strip_summary(plan)
    return {
        "plan": plan,
        "llm_refined": llm_applied,
        "dirty": dirty,
        "live": strip,
    }


# ── Phase 4: LLM-assisted ranking (flat scores only) ────────────────────

def scores_are_flat(
    candidates: list[dict[str, Any]],
    *,
    top_n: int = 5,
    relative_epsilon: float | None = None,
) -> bool:
    """True when the top candidates are nearly tied on composite score."""
    eps = relative_epsilon
    if eps is None:
        eps = env_float("ATLAS_ORCH_FLAT_EPS", 0.08)
    ready = [
        c for c in (candidates or [])
        if c.get("status") == "ready"
    ][: max(2, top_n)]
    if len(ready) < 2:
        return False
    scores = [float(c.get("score") or 0) for c in ready]
    hi, lo = max(scores), min(scores)
    if hi <= 0:
        return True
    return ((hi - lo) / hi) < eps


def _parse_index_order(text: str, n: int) -> list[int] | None:
    """Extract a permutation (or partial order) of indices 0..n-1 from LLM text."""
    raw = (text or "").strip()
    if not raw:
        return None
    # Prefer JSON array
    try:
        # Find first [...] block
        m = re.search(r"\[[\s\d,]+\]", raw)
        blob = m.group(0) if m else raw
        data = json.loads(blob)
        if isinstance(data, list):
            idxs = [int(x) for x in data if str(x).isdigit() or isinstance(x, int)]
            idxs = [i for i in idxs if 0 <= i < n]
            # dedupe preserve order
            seen: set[int] = set()
            out: list[int] = []
            for i in idxs:
                if i not in seen:
                    seen.add(i)
                    out.append(i)
            if out:
                return out
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    # Fallback: integers in order
    nums = [int(x) for x in re.findall(r"\b\d+\b", raw)]
    nums = [i for i in nums if 0 <= i < n]
    seen2: set[int] = set()
    out2: list[int] = []
    for i in nums:
        if i not in seen2:
            seen2.add(i)
            out2.append(i)
    return out2 or None


def apply_llm_order(
    candidates: list[dict[str, Any]],
    order: list[int],
) -> list[dict[str, Any]]:
    """Reorder candidates by LLM index order; append untouched tail.

    Bumps ``score`` slightly so the preferred order survives later sorts,
    and stamps ``ranking_source=llm`` on touched entries.
    """
    if not candidates or not order:
        return candidates
    n = len(candidates)
    used: set[int] = set()
    reordered: list[dict[str, Any]] = []
    base = max(float(c.get("score") or 0) for c in candidates) + 1.0
    for rank, idx in enumerate(order):
        if not (0 <= idx < n) or idx in used:
            continue
        used.add(idx)
        item = dict(candidates[idx])
        item["score"] = round(base - rank * 0.01, 4)
        item["ranking_source"] = "llm"
        reordered.append(item)
    for i, c in enumerate(candidates):
        if i not in used:
            item = dict(c)
            item.setdefault("ranking_source", "deterministic")
            reordered.append(item)
    return reordered


def llm_refine_ranking(
    candidates: list[dict[str, Any]],
    *,
    focus_text: str,
    llm_client: Any,
    max_candidates: int | None = None,
) -> list[dict[str, Any]]:
    """Ask the LLM to order a fixed candidate list. Never invents new actions."""
    cap = max_candidates
    if cap is None:
        cap = env_int("ATLAS_ORCH_LLM_RANK_MAX", 8)
    cap = max(2, min(int(cap), 12))
    subset = [
        c for c in candidates
        if c.get("status") == "ready"
    ][:cap]
    if len(subset) < 2:
        return candidates

    payload = [
        {
            "i": i,
            "path": c.get("path"),
            "tool_hint": c.get("tool_hint"),
            "capability_id": c.get("capability_id"),
            "detail_level": c.get("detail_level"),
            "investigation_value": c.get("investigation_value"),
            "score": c.get("score"),
            "est_tokens": c.get("est_tokens"),
            "cost_class": c.get("cost_class"),
        }
        for i, c in enumerate(subset)
    ]
    prompt = (
        "You are a DFIR lead investigator. Rank the NEXT investigative "
        "actions for maximum investigative value under resource constraints.\n"
        "Rules:\n"
        "- Return ONLY a JSON array of the candidate indices in preferred "
        "order (e.g. [2,0,1]).\n"
        "- Use only indices that appear in the list. Do not invent paths "
        "or tools.\n"
        "- Prefer actions that answer open tasks; prefer cheaper/disk-first "
        "when value is similar.\n\n"
        f"Investigation focus:\n{(focus_text or '')[:1200]}\n\n"
        f"Candidates:\n{json.dumps(payload, indent=2)}\n"
    )
    resp = llm_client.chat(
        [{"role": "user", "content": prompt}],
        tools=None,
        temperature=0.0,
    )
    content = getattr(resp, "content", None) or ""
    order = _parse_index_order(content, len(subset))
    if not order:
        return candidates
    refined_subset = apply_llm_order(subset, order)
    # Splice back: refined top + remaining original not in subset
    subset_paths = {c.get("path") for c in subset}
    tail = [c for c in candidates if c.get("path") not in subset_paths]
    return refined_subset + tail


def maybe_llm_refine_ranking(
    plan: dict[str, Any],
    *,
    case_dir: str | os.PathLike,
    llm_client: Any = None,
    turn: int = 0,
) -> tuple[dict[str, Any], bool]:
    """Apply LLM ranking when enabled and scores are flat. Fail-open."""
    mode = (os.environ.get("ATLAS_ORCH_LLM_RANK") or "auto").strip().lower()
    if mode in ("0", "off", "false", "no"):
        return plan, False
    cands = list(plan.get("candidates") or [])
    if not scores_are_flat(cands):
        if mode not in ("1", "on", "always", "force"):
            return plan, False
    if llm_client is None:
        return plan, False

    # Throttle: at most once per ATLAS_ORCH_LLM_RANK_EVERY turns (default 5),
    # unless dirty rebuild or force mode.
    every = env_int("ATLAS_ORCH_LLM_RANK_EVERY", 5)
    every = max(1, every)
    meta_path = _llm_meta_path(case_dir)
    last_turn = -10_000
    try:
        if meta_path.is_file():
            last_turn = int(json.loads(meta_path.read_text()).get("turn") or 0)
    except Exception:
        pass
    force = mode in ("1", "on", "always", "force")
    if not force and turn and (turn - last_turn) < every:
        return plan, False

    focus = ""
    try:
        focus = str((plan.get("resources") or {}).get("focus_text_preview") or "")
        if not focus:
            from core.investigation_tasks import load_tasks
            tasks = load_tasks(case_dir).get("tasks") or []
            focus = " ".join(
                (t.get("text") or "")
                for t in tasks
                if t.get("status") in {
                    "open", "in_progress", "partial", "reopened",
                }
            )
    except Exception:
        pass

    refined = llm_refine_ranking(
        cands,
        focus_text=focus,
        llm_client=llm_client,
    )
    if refined is cands or refined == cands:
        return plan, False
    # Detect actual reorder
    before = [c.get("path") for c in cands[:5]]
    after = [c.get("path") for c in refined[:5]]
    if before == after and not any(
        c.get("ranking_source") == "llm" for c in refined[:5]
    ):
        return plan, False

    plan = dict(plan)
    plan["candidates"] = refined
    resources = dict(plan.get("resources") or {})
    resources["ranking_source"] = "llm"
    plan["resources"] = resources
    # Update orchestrate step summary if present
    for s in plan.get("steps") or []:
        if s.get("id") == "step-orchestrate" and refined:
            top = refined[:5]
            s["summary"] = (
                f"Orchestrator (LLM-refined): prefer "
                + ", ".join(
                    f"{c.get('path')} [{c.get('tool_hint')}|score={c.get('score')}]"
                    for c in top
                )
            )
            break
    try:
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        meta_path.write_text(
            json.dumps({"turn": turn, "ts": time.time()}),
            encoding="utf-8",
        )
    except OSError:
        pass
    return plan, True
