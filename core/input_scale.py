"""Input Scale — cost sensor + hard safety floors for bulk forensic tools.

Feeds the Context Budget Manager with size/shard estimates. Middleware uses
``check()`` to soft-refuse calls that cannot fit the remaining tool-output
budget (or absolute floors). Investigation affinity re-orders shards when
task/plan text is available; otherwise size + name heuristics apply.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from core.envfile import env_int
from core.paths import INPUT_PATH_PARAM_NAMES

MAX_DIR_FILES = env_int("ATLAS_INPUT_MAX_DIR_FILES", 1)
MAX_FILE_BYTES = env_int("ATLAS_INPUT_MAX_FILE_BYTES", 64 * 1024 * 1024)
SHARD_LIST_CAP = env_int("ATLAS_INPUT_SHARD_LIST_CAP", 25)

_BULK_PARSE_RE = re.compile(
    r"(?:ez_ez_evtxecmd|ez_evtxecmd|ez_ez_mftecmd|ez_mftecmd|"
    r"misc_evtx_|misc_chainsaw|hayabusa_|"
    r"plaso_|yara_yara_scan|yara_scan|carve_|"
    r"job_job_start_hayabusa)",
    re.IGNORECASE,
)

_NARROWING_ARGS = frozenset({
    "event_ids", "inc", "pattern", "where", "query", "regex",
    "start", "end", "time_start", "time_end", "since", "until",
    "limit", "max_events", "plugin",
})

_EVTX_EXT = {".evtx"}
_BULK_EXTS = {
    ".evtx", ".pcap", ".pcapng", ".e01", ".vmdk", ".raw", ".dd",
    ".mem", ".dmp", ".vmem", ".mft",
}

_AFFINITY_RULES: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("rdp", "terminal services", "remote desktop", "nla"),
     ("terminalservices", "remotcon", "rdpclient", "rdpcore")),
    (("bitlocker", "tpm", "fve"),
     ("bitlocker", "fve", "tpm")),
    (("usb", "removable", "thumb drive", "pnp"),
     ("kernel-pnp", "driverframeworks", "usbstor", "wpd-mtp")),
    (("lateral", "psexec", "wmi", "smb", "pass-the-hash", "pth", "auth"),
     ("security", "sysmon", "microsoft-windows-smb", "powershell")),
    (("firewall", "vpn"),
     ("firewall", "ras", "security")),
    (("powershell", "scriptblock"),
     ("powershell", "scriptblock")),
    (("defender", "malware", "amsi"),
     ("windows defender", "amsi", "security")),
)


def is_bulk_parse_tool(tool_name: str) -> bool:
    return bool(_BULK_PARSE_RE.search(tool_name or ""))


def _has_narrowing(args: dict) -> bool:
    for k in _NARROWING_ARGS:
        v = args.get(k)
        if v is None or v == "":
            continue
        if isinstance(v, (list, tuple, dict)) and not v:
            continue
        return True
    return False


def _input_paths(args: dict) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for key in INPUT_PATH_PARAM_NAMES:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            out.append((key, os.path.expanduser(val.strip())))
    return out


def _dir_children(path: str, exts: set[str] | None = None) -> list[Path]:
    root = Path(path)
    if not root.is_dir():
        return []
    kids: list[Path] = []
    try:
        for p in root.iterdir():
            if not p.is_file():
                continue
            if exts and p.suffix.lower() not in exts:
                continue
            kids.append(p)
    except OSError:
        return []
    return kids


def estimate_path_cost_tokens(path: str) -> int:
    try:
        st = os.stat(path)
    except OSError:
        return 0
    if os.path.isdir(path):
        total = 0
        for child in _dir_children(path, _BULK_EXTS)[:500]:
            try:
                total += child.stat().st_size
            except OSError:
                continue
        return max(50_000, total // 50)
    return max(500, st.st_size // 100)


def affinity_score(path: str, focus_text: str) -> float:
    """Public alias for investigation-driven path scoring."""
    return _affinity_score(path, focus_text)


def _affinity_score(path: str, focus_text: str) -> float:
    text = (focus_text or "").casefold()
    name = path.replace("\\", "/").casefold()
    score = 0.0
    if not text:
        base = Path(path).name.casefold()
        if base == "security.evtx":
            score += 5.0
        elif base in ("system.evtx", "application.evtx"):
            score += 3.0
        elif "diagnostic" in base or "operational" in base:
            score -= 1.0
        return score
    for keywords, needles in _AFFINITY_RULES:
        if any(k in text for k in keywords):
            if any(n in name for n in needles):
                score += 8.0
    base = Path(path).stem.casefold()
    # Prefer the canonical Security.evtx over similarly named channels when
    # authentication / lateral-movement vocabulary is in focus.
    if base == "security" and any(
            k in text for k in (
                "auth", "logon", "lateral", "admin", "vpn",
                "credential", "bruteforce", "spray")):
        score += 6.0
    for tok in re.findall(r"[a-z0-9]{4,}", text):
        if tok in base or tok in name:
            score += 1.5
    if "diagnostic" in name and "diagnostic" not in text:
        score -= 2.0
    if "adminless" in name and "adminless" not in text:
        score -= 1.5
    return score


def _focus_text_from_case(case_dir: str | None) -> str:
    if not case_dir:
        return ""
    parts: list[str] = []
    root = Path(case_dir)
    for rel in (
        ".atlas/investigation_tasks.json",
        ".atlas/investigation_plan.json",
        "CASE.md",
    ):
        path = root / rel
        if not path.is_file():
            continue
        try:
            parts.append(
                path.read_text(encoding="utf-8", errors="replace")[:80_000])
        except OSError:
            continue
    return "\n".join(parts)


def rank_shards(
    paths: list[Path],
    *,
    focus_text: str = "",
    cap: int = SHARD_LIST_CAP,
) -> list[dict[str, Any]]:
    scored: list[tuple[float, Path, int]] = []
    for p in paths:
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        scored.append((_affinity_score(str(p), focus_text), p, size))
    scored.sort(key=lambda t: (-t[0], t[2], t[1].name.lower()))
    out: list[dict[str, Any]] = []
    for aff, p, size in scored[:cap]:
        out.append({
            "path": str(p),
            "bytes": size,
            "affinity": round(aff, 2),
            "est_tokens": estimate_path_cost_tokens(str(p)),
        })
    return out


def should_force_artifact_only(
    tool_name: str,
    args: dict,
    *,
    available_tool_tokens: int | None = None,
) -> bool:
    """True when a bulk parse may run but must not dump into the LLM.

    Disk-first bootstrap: large single files without narrowing filters are
    allowed to execute (write CSV/JSON on disk) while agent-facing output is
    forced through artifact_ready + profile compaction.
    """
    if not is_bulk_parse_tool(tool_name):
        return False
    try:
        from core.llm_check import session_limits
        lim = session_limits()
        if lim is not None and lim.disk_first:
            return True
    except Exception:
        pass
    if _has_narrowing(args):
        return False
    tool_budget = (
        available_tool_tokens if available_tool_tokens is not None else 8_000)
    for _key, path in _input_paths(args):
        if not path or not os.path.exists(path) or os.path.isdir(path):
            continue
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        est = estimate_path_cost_tokens(path)
        if size > MAX_FILE_BYTES or est > tool_budget:
            return True
    return False


def _prior_identical_refusals(tool_name: str, path: str) -> int:
    """Count earlier input_scale abandons of the same tool + directory.

    Read from the live execution trace (fail-open): the middleware records
    each refusal as call_abandoned with reason
    "input_scale: <tool> refused: directory '<path>' …".
    """
    try:
        from core.execution_log import log
        needle_tool = str(tool_name)
        needle_path = repr(str(path))
        n = 0
        for e in log._entries:
            if e.get("type") != "call_abandoned":
                continue
            reason = str(e.get("reason") or "")
            if (reason.startswith("input_scale")
                    and needle_tool in reason and needle_path in reason):
                n += 1
        return n
    except Exception:
        return 0


def check(
    tool_name: str,
    args: dict,
    *,
    case_dir: str | None = None,
    available_tool_tokens: int | None = None,
    max_dir_files: int | None = None,
) -> dict[str, Any] | None:
    """Return a refusal dict if the call is over scale/budget, else None.

    Large **single files** without filters are not refused — they run
    disk-first (see ``should_force_artifact_only``). Multi-file directories and
    over-budget directory aggregates still refuse with a shard plan.
    """
    if not is_bulk_parse_tool(tool_name):
        return None

    dir_limit = max_dir_files if max_dir_files is not None else MAX_DIR_FILES
    dir_limit = max(1, min(int(dir_limit), 8))
    tool_budget = (
        available_tool_tokens if available_tool_tokens is not None else 8_000)
    focus = _focus_text_from_case(case_dir)
    narrowing = _has_narrowing(args)

    for key, path in _input_paths(args):
        if not path or not os.path.exists(path):
            continue

        if os.path.isdir(path):
            kids = (_dir_children(path, _EVTX_EXT)
                    or _dir_children(path, _BULK_EXTS))
            if not kids:
                try:
                    kids = [p for p in Path(path).iterdir() if p.is_file()][:500]
                except OSError:
                    kids = []
            if len(kids) > dir_limit:
                shards = rank_shards(kids, focus_text=focus)
                example = dict(args)
                if shards:
                    example[key] = shards[0]["path"]
                # Escalate identical repeats: the same directory refusal can be
                # issued again and again when the ranked shards sit in a side
                # field the model skips. From the second repeat on, put the concrete file
                # paths INSIDE the error text and bar the directory call.
                repeats = _prior_identical_refusals(tool_name, path)
                top_paths = [s["path"] for s in shards[:3]]
                if repeats >= 1 and top_paths:
                    err = (
                        f"REPEATED REFUSAL (#{repeats + 1}) — {tool_name} on "
                        f"directory {path!r} was already refused with this "
                        f"exact reason. STOP passing this directory. Call "
                        f"{tool_name} with exactly ONE of these files next: "
                        + " | ".join(top_paths)
                    )
                else:
                    err = (
                        f"{tool_name} refused: directory {path!r} has "
                        f"{len(kids)} files; context budget allows at most "
                        f"{dir_limit} per call. Pass one file (or a filtered "
                        f"subset) — do not re-pass the whole directory."
                        + (f" Highest-value files: {' | '.join(top_paths)}"
                           if top_paths else "")
                    )
                return {
                    "success": False,
                    "gate": "input_scale",
                    "error": err,
                    "hint": (
                        "Disk-first: parse the highest-affinity single file "
                        "(stdout will be compacted to artifact_ready + "
                        "profile). Then query the CSV with table.*. "
                        "Full coverage = table windows later, not a dir dump."
                    ),
                    "shards": shards,
                    "next_call_example": {
                        "tool": tool_name,
                        "arguments": example,
                    },
                    "available_for_tool_output_tokens": tool_budget,
                }
            est = estimate_path_cost_tokens(path)
            if est > tool_budget and not narrowing and len(kids) > 1:
                shards = rank_shards(kids or [Path(path)], focus_text=focus)
                example = dict(args)
                if shards:
                    example[key] = shards[0]["path"]
                return {
                    "success": False,
                    "gate": "context_budget",
                    "error": (
                        f"{tool_name} refused: estimated dump "
                        f"~{est} tokens exceeds remaining tool-output budget "
                        f"~{tool_budget}. Narrow to one file."
                    ),
                    "hint": (
                        "Pick a single high-affinity file from shards for a "
                        "disk-first parse."
                    ),
                    "shards": shards,
                    "next_call_example": {
                        "tool": tool_name,
                        "arguments": example,
                    },
                    "available_for_tool_output_tokens": tool_budget,
                }
            continue

        # Single files: never refuse for size alone — disk-first + compact.
        # (should_force_artifact_only handles agent-facing compaction.)
        _ = narrowing
    return None
