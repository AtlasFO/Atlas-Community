"""Evidence-compatibility checks for Atlas tools.

Design:
  - Hard refuse only when a tool *requires* evidence classes the case lacks.
  - Unknown / untagged tools fail open (LLM keeps flexibility).
  - No investigation playbooks ("if CSV then always table_grep") — only
    physical impossibility constraints.

Tool identity forms accepted:
  - MCP names: ``ewf_ewf_mount``, ``ez_ez_evtxecmd``
  - Dotted aliases: ``ewf.ewf_mount``, ``ez.evtxecmd``
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterable, Optional

from core.evidence_profile import present_class_set

# Capability-manifest evidence tags → profile classes that satisfy them.
CAPABILITY_EVIDENCE_TO_PROFILE: dict[str, frozenset[str]] = {
    "all": frozenset({"*"}),
    "disk": frozenset({"disk"}),
    "mounted_fs": frozenset({"disk"}),
    "memory": frozenset({"memory"}),
    "pcap": frozenset({"pcap"}),
    "logs": frozenset({"tabular", "windows_eventlog"}),
    "siem_export": frozenset({"tabular"}),
    "file": frozenset({"file", "tabular", "email", "disk", "memory", "pcap",
                       "windows_eventlog"}),
    "live": frozenset({"live"}),
}

# Always-compatible MCP name prefixes (control plane / meta / always-safe).
_ALWAYS_PREFIXES: tuple[str, ...] = (
    "reason_",
    "dair_",
    "claim_",
    "hash_",
    "strings_",
    "enrich_",
    "accuracy_",
    "coverage_",
    "correlate_",
    "attribution_",
    "job_",
    "export_",
    "search_",
    "deob_",
    "crypto_",
    "monitor_",
    "velo_",
    "respond_",
    "misc_start_execution",
    "misc_export_execution",
    "misc_write_",
    "misc_record_",
    "misc_serve_",
    "misc_current_investigation",
    "misc_batch_run",  # shell; typed forensic binaries still MCP-routed
    "misc_knowns_",
    "misc_capa_",
    "misc_pe_",
    "misc_densityscout_",
    "misc_clamscan_",
    "misc_olevba_",
    "misc_mraptor_",
    "misc_parse_email",
    "misc_readpst_",
    "misc_pff_",
    "misc_device_install_",
    "yara_",
)

# Ordered rules: first match wins. Each entry is
# (match_prefixes_or_substrings, requires_any_profile_classes).
# requires_any = empty → always allow (should not appear).
#
# Structural split (do NOT add per-tool soft-gates):
#   - Image/volume openers → ``disk`` only (they open E01/VMDK/raw media).
#   - Path-consuming artifact parsers → ``file`` OR ``disk`` (KAPE/loose
#     exports classify as file; a disk image also satisfies them).
#   - Class-specific hunters (EVTX, memory, pcap, …) keep their class,
#     with ``disk`` as optional fallback where the artifact may live inside
#     an image.
_REQUIREMENT_RULES: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    # Disk image / filesystem tooling (open media — not loose files)
    (("ewf_",), ("disk",)),
    (("tsk_",), ("disk",)),
    (("img_",), ("disk",)),
    (("plaso_",), ("disk",)),
    (("carve_",), ("disk",)),
    # Memory
    (("vol_",), ("memory",)),
    (("yara_yara_scan_memory", "yara_scan_memory"), ("memory",)),
    # PCAP / packet tools (not all of net.* — keep narrow)
    (("net_tcpdump", "net_ngrep", "net_http_session", "net_pcap",
      "net_tcpxtract"), ("pcap",)),
    # Tabular exports
    (("table_",), ("tabular",)),
    # $MFT consumers take an extracted $MFT file or a disk image.
    (("misc_analyzemft", "misc_mft_rule_hunt"), ("file", "disk")),
    # Event-log hunters — need EVTX class, or a disk image that may hold them
    (("ez_ez_evtxecmd", "ez_evtxecmd", "misc_evtx_", "misc_chainsaw",
      "hayabusa_", "job_job_start_hayabusa"),
     ("windows_eventlog", "disk")),
    # Path-consuming Windows artifact parsers (EZ + common misc parsers).
    # Matched AFTER the EVTX-specific rule. Prefix ``ez_`` covers every
    # current and future EZ path tool without naming RECmd/MFTECmd/….
    (("ez_", "misc_regripper", "misc_usnparser"),
     ("file", "disk")),
    # ESE databases (SRUM, WebCache, Windows.edb) and pre-Vista .evt logs:
    # loose files, or inside an image.
    (("ese_",), ("file", "disk")),
    (("evt_",), ("windows_eventlog", "file", "disk")),
    # Anti-forensics on disk/memory artifacts
    (("af_af_", "af_"), ("disk", "memory", "file")),
    # Live endpoint
    (("live_",), ("live",)),
)

# Suggested first-load namespaces from present classes (LLM may still load more).
# Disk order is load-bearing under the 128-schema budget: image openers
# (img/tsk) must precede heavy parsers (ez) and E01-only ewf — otherwise
# mixed disk+tabular cases pack to 117/128 and permanently refuse tsk
#
_CLASS_SUGGESTED_NAMESPACES: dict[str, tuple[str, ...]] = {
    "tabular": ("table",),
    "disk": ("img", "tsk", "ewf", "ez"),
    # Loose / KAPE file trees — path parsers, not image openers
    "file": ("ez",),
    "memory": ("vol",),
    "pcap": ("net",),
    "windows_eventlog": ("ez", "hayabusa"),
    "email": ("misc",),
    "live": ("live",),
}

ALWAYS_CORE_NAMESPACES: tuple[str, ...] = (
    "misc", "reason", "dair", "hash", "coverage", "brain",
)


def normalize_tool_name(tool_name: str) -> str:
    """Normalize dotted or doubled names to underscore MCP form for matching."""
    name = (tool_name or "").strip()
    if not name:
        return ""
    if "." in name and "_" not in name.split(".", 1)[0]:
        # dotted alias ewf.ewf_mount / ez.evtxecmd
        ns, rest = name.split(".", 1)
        rest = rest.replace(".", "_")
        if not rest.startswith(ns + "_"):
            return f"{ns}_{ns}_{rest}"
        return f"{ns}_{rest}"
    return name.replace(".", "_")


def _matches(tool_name: str, needles: Iterable[str]) -> bool:
    return any(tool_name.startswith(n) or n in tool_name for n in needles)


def required_classes_for_tool(tool_name: str) -> Optional[frozenset[str]]:
    """Return required profile classes (ANY-of), or None if unrestricted."""
    name = normalize_tool_name(tool_name)
    if not name:
        return None
    if any(name.startswith(p) for p in _ALWAYS_PREFIXES):
        return None
    for prefixes, required in _REQUIREMENT_RULES:
        if _matches(name, prefixes):
            return frozenset(required)
    return None


def tool_compatible(
    tool_name: str,
    present: frozenset[str] | set[str] | None,
) -> tuple[bool, str]:
    """Return (ok, reason). ok=True means call may proceed."""
    required = required_classes_for_tool(tool_name)
    if required is None:
        return True, "unrestricted"
    present = frozenset(present or ())
    if present & required:
        return True, "compatible"
    need = ", ".join(sorted(required))
    have = ", ".join(sorted(present)) if present else "(none)"
    return False, (
        f"evidence-compat: tool {tool_name!r} requires one of [{need}] "
        f"but this case only has [{have}]. Pick a tool whose requirements "
        f"intersect present evidence classes — do not retry this tool."
    )


def named_input_classes(
    args: dict[str, Any] | None,
    case_dir: str | os.PathLike | None = None,
) -> set[str]:
    """Evidence classes of the files a call actually names in its arguments.

    Only existing regular files count: a directory or a path that is not
    there tells nothing about what the tool would read. Relative paths are
    resolved against the case directory the way the wrappers resolve them.
    """
    from core.evidence_profile import classify_path
    from core.paths import INPUT_PATH_PARAM_NAMES

    classes: set[str] = set()
    for key in INPUT_PATH_PARAM_NAMES:
        raw = (args or {}).get(key)
        if not isinstance(raw, str) or not raw.strip():
            continue
        path = Path(os.path.expanduser(raw.strip()))
        if not path.is_absolute() and case_dir:
            path = Path(case_dir) / path
        try:
            if path.is_file():
                classes.add(classify_path(path))
        except OSError:
            continue
    return classes


def check_tool_against_profile(
    tool_name: str,
    profile: dict[str, Any] | None,
    *,
    args: dict[str, Any] | None = None,
    case_dir: str | os.PathLike | None = None,
) -> Optional[dict[str, Any]]:
    """Return a refusal dict if incompatible, else None.

    The profile answers "does this case hold evidence of a kind this tool
    works on". When the call names an input that exists, the better
    question is "can this tool read *that* file" — a CSV the run parsed
    itself sits in the case and is readable by the table tools whatever
    the profile inferred, and the first parse of a kind has not yet added
    its class to the profile. So a named, existing file whose own class
    satisfies the tool's requirement passes. Calls that name no input keep
    the profile check, which is what stops a memory tool on a case that
    holds no memory image.
    """
    present = present_class_set(profile)
    ok, reason = tool_compatible(tool_name, present)
    if ok:
        return None
    required = required_classes_for_tool(tool_name) or frozenset()
    named = named_input_classes(args, case_dir) if args else set()
    if named & required:
        return None
    return {
        "success": False,
        "error": reason,
        "gate": "evidence_compat",
        "tool": tool_name,
        "required_any": sorted(required),
        "present_classes": sorted(present),
        "named_input_classes": sorted(named),
    }


def capability_available(
    capability_evidence_tags: Iterable[str],
    present: frozenset[str] | set[str],
) -> bool:
    """Whether a capability's evidence tags are satisfiable by the profile."""
    tags = list(capability_evidence_tags) or ["all"]
    if "all" in tags:
        return True
    present = frozenset(present or ())
    for tag in tags:
        mapped = CAPABILITY_EVIDENCE_TO_PROFILE.get(tag)
        if mapped is None:
            continue
        if "*" in mapped or (present & mapped):
            return True
    return False


def suggested_core_namespaces(profile: dict[str, Any] | None) -> tuple[str, ...]:
    """Namespaces to preload from present classes — still LLM-overridable."""
    present = present_class_set(profile)
    # The tools a run needs to start and close are listed whatever is loaded
    # (the toolbox's control plane), so the preload order can put the
    # namespaces the evidence calls for ahead of the optional rest of the
    # core. Packed the other way round, a budget that fit the core and one
    # small namespace left the primary evidence's tools out of the list.
    ordered: list[str] = ["reason", "dair"]
    for cls in ("tabular", "windows_eventlog", "file", "disk", "memory", "pcap",
                "email", "live"):
        if cls not in present:
            continue
        for ns in _CLASS_SUGGESTED_NAMESPACES.get(cls, ()):
            if ns not in ordered:
                ordered.append(ns)
    for ns in ALWAYS_CORE_NAMESPACES:
        if ns not in ordered:
            ordered.append(ns)
    # Never preload ewf/tsk/vol without the matching class (defense in depth).
    if "disk" not in present:
        ordered = [n for n in ordered if n not in ("ewf", "img", "tsk")]
    if "memory" not in present:
        ordered = [n for n in ordered if n != "vol"]
    if "pcap" not in present:
        ordered = [n for n in ordered if n != "net"]
    if "live" not in present:
        ordered = [n for n in ordered if n != "live"]
    # When disk is present the openers pack in their working order, image
    # first, right behind the reasoning namespaces and ahead of everything
    # optional: budget packing is order-sensitive, and a list that ran out
    # before the openers left a disk case unable to open its own evidence.
    if "disk" in present:
        openers = [ns for ns in ("img", "tsk", "ewf", "ez") if ns in ordered]
        rest = [n for n in ordered if n not in openers]
        lead = [n for n in rest if n in ("reason", "dair")]
        ordered = lead + openers + [n for n in rest if n not in lead]
    # The general namespace goes right behind the reasoning pair, ahead of
    # the openers and the optional rest of the core. The playbook's first
    # working calls live in it, and a list packed without it left the
    # analyst narrating its calls instead of making them, although the
    # control plane was listed. Packing is order-sensitive, so what a tight
    # ceiling leaves out is the tail, never this.
    lead = [n for n in ("reason", "dair", "misc") if n in ordered]
    ordered = lead + [n for n in ordered if n not in lead]
    return tuple(ordered)


def format_compat_summary_for_prompt(profile: dict[str, Any] | None) -> str:
    """Short addon listing which capability families look viable."""
    if not profile:
        return ""
    present = present_class_set(profile)
    try:
        from tools.tool_capabilities import tool_capability_manifest
        caps = tool_capability_manifest().get("capabilities") or []
    except Exception:
        return ""
    viable: list[str] = []
    unavailable: list[str] = []
    for cap in caps:
        cid = cap.get("id") or "?"
        tags = cap.get("evidence") or ["all"]
        if capability_available(tags, present):
            viable.append(cid)
        else:
            unavailable.append(cid)
    lines = [
        "",
        "Capability families vs this profile (advisory — final tool choice is yours):",
        f"  - likely viable: {', '.join(viable) if viable else '(none)'}",
        f"  - likely unavailable: {', '.join(unavailable) if unavailable else '(none)'}",
    ]
    return "\n".join(lines)
