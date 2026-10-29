"""Curated Atlas tool capability manifest.

The manifest is intentionally small and semantic. It is not a full inventory of
every MCP wrapper; it is the planning vocabulary DAIR/reasoning should use when
choosing the next batch. Focused wrappers can still exist outside this list, but
priority_tools should come from these known, phase-appropriate capabilities.
"""
from __future__ import annotations

import copy
import fnmatch
import os
import re
from typing import Any, Callable, Optional


MANIFEST_VERSION = "2026-09-28.1"


_CAPABILITIES: list[dict] = [
    {
        "id": "reasoning_control",
        "phases": ["Triage", "Analyze", "Report"],
        "evidence": ["all"],
        "purpose": "Plan, hypothesize, challenge, and prepare report synthesis.",
        "tools": [
            "reason.plan",
            "reason.hypothesize",
            "reason.evaluate_finding",
            "reason.confidence_score",
            "reason.cite_check",
            "reason.synthesize",
            "reason.pre_report_check",
            "claim.snapshot",
            "claim.add_observation",
            "claim.add_claim",
            "claim.add_hypothesis",
            "claim.add_conflict",
            "claim.promote_conclusion",
            "claim.supersede",
            "claim.revalidate",
            "claim.resolve_conflict",
            "claim.detect_contradictions",
            "claim.record_recommendation",
            "claim.update_recommendation",
            "claim.list_recommendations",
            "misc.current_investigation_state",
            "misc.write_projected_final_report",
            "misc.write_final_report",
        ],
    },
    {
        "id": "memory_process_network",
        "phases": ["Triage", "Analyze", "Scan"],
        "evidence": ["memory"],
        "purpose": "Enumerate processes, command lines, sessions, injected memory, and network sockets from memory.",
        "tools": [
            "vol.psscan",
            "vol.pslist",
            "vol.pstree",
            "vol.cmdline",
            "vol.sessions",
            "vol.netscan",
            "vol.netstat",
            "vol.malfind",
            "vol.filescan",
            "vol.dumpfiles",
            "vol.yarascan",
        ],
    },
    {
        "id": "disk_filesystem_timeline",
        "phases": ["Collect", "Analyze"],
        "evidence": ["disk", "mounted_fs"],
        "purpose": (
            "Collect filesystem listings, file bodies, execution artifacts, "
            "and timeline data. Open a disk image with tsk.mmls → tsk.fls; a "
            "VMDK, VHD, VHDX, QCOW2 or VDI is read through the raw view Atlas "
            "makes of it, its snapshot chain applied (the mount plan entry "
            "names a copy, img.vmdk_export_raw, where a host has no views). "
            "A base VMDK shadowed by snapshot deltas is an earlier state "
            "(img.vmdk_chain_info names the chain top). Not loop/FUSE mounts "
            "as the Triage default."
        ),
        "tools": [
            "tsk.mmls",
            "tsk.fls",
            "tsk.icat",
            "tsk.istat",
            "tsk.mactime",
            "img.vmdk_chain_info",
            "img.vmdk_export_raw",
            "ez.mftecmd",
            "ez.mftecmd_usn",
            "misc.analyzemft_parse",
            "misc.mft_rule_hunt",
            "ez.jlecmd",
            "ez.lecmd",
            "ez.pecmd",
            "misc.usnparser_parse",
            "misc.onedrive_odl",
            "plaso.create_timeline",
            "plaso.export_csv",
        ],
    },
    {
        "id": "windows_registry_identity",
        "phases": ["Collect", "Analyze"],
        "evidence": ["disk", "memory"],
        "purpose": "Resolve registry persistence, account bindings, app execution, and identity clues.",
        "tools": [
            "ez.recmd_hive",
            "ez.recmd_dir",
            "ez.recmd_batch",
            "ez.amcacheparser",
            "ez.appcompatcacheparser",
            "ez.recentfilecache",
            "misc.regripper_hive",
            "vol.registry_hivelist",
            "vol.registry_printkey",
            "vol.userassist",
            "vol.getsids",
        ],
    },
    {
        "id": "windows_usage_databases",
        "phases": ["Collect", "Analyze"],
        "evidence": ["disk", "file"],
        "purpose": "Read the ESE databases Windows keeps usage in: SRUM (per-application network bytes, CPU and energy over about 30 days), Server User Access Logging (who used which server role from where, day by day), WebCache (legacy IE/Edge history), Windows.edb (search index) and any other .edb/.dat ESE store.",
        "tools": [
            "ez.srumecmd",
            "ez.sumecmd",
            "ese.esedb_info",
            "ese.esedb_export",
        ],
    },
    {
        "id": "windows_event_logs",
        "phases": ["Collect", "Analyze"],
        "evidence": ["disk", "live"],
        "purpose": "Parse Windows event logs for authentication, service, task, PowerShell, and timeline events.",
        "tools": [
            "ez.evtxecmd",
            "evt.evt_export",
            "misc.evtx_filter",
            "misc.evtx_dump",
            "misc.chainsaw_hunt",
            "hayabusa.triage",
            "hayabusa.summary",
            "job.job_start_hayabusa",
            "live.live_event_log_tail",
        ],
    },
    {
        "id": "tabular_export_analysis",
        "phases": ["Triage", "Collect", "Analyze"],
        "evidence": ["logs", "siem_export", "disk"],
        "purpose": "Query SIEM/EDR/cloud exports shipped as xlsx, csv/tsv, or "
                   "jsonl: schema discovery, filtered queries, group-by "
                   "pivots, IOC regex sweeps.",
        "tools": [
            "table.table_schema",
            "table.table_query",
            "table.table_pivot",
            "table.table_grep",
        ],
    },
    {
        "id": "network_pcap",
        "phases": ["Triage", "Collect", "Analyze", "Scan"],
        "evidence": ["pcap"],
        "purpose": "Extract DNS, HTTP, sessions, identities, IPs, and payload streams from packet captures.",
        "tools": [
            "net.tcpdump_read",
            "net.tcpdump_list_connections",
            "net.tcpdump_extract_ips",
            "net.tcpdump_extract_dns",
            "net.tcpdump_extract_http",
            "net.http_session_inventory",
            "net.pcap_identity_timeline",
            "net.ngrep_search",
            "net.tshark_export_objects",
            "net.tcpxtract_streams",
        ],
    },
    {
        "id": "static_file_triage",
        "phases": ["Triage", "Analyze", "Scan"],
        "evidence": ["file", "mounted_fs"],
        "purpose": "Identify, hash, grep, inspect, and classify files or extracted payloads.",
        "tools": [
            "strings.stat_file",
            "strings.file_identify",
            "strings.strings_grep",
            "strings.read_text",
            "strings.floss_extract",
            "hash.hash_file",
            "hash.hash_directory",
            "hash.verify_evidence_hash",
            "misc.capa_analyze",
            "misc.pe_scanner",
            "misc.densityscout_scan",
        ],
    },
    {
        "id": "deobfuscation",
        "phases": ["Triage", "Analyze"],
        "evidence": ["file"],
        "purpose": "Deterministically decode obfuscated scripts, maldocs, and encoded payloads (base64/hex/XOR, PowerShell -EncodedCommand, decode chains).",
        "tools": [
            "deob.decode_chain",
            "deob.hex_decode",
            "deob.xor_bruteforce",
            "deob.base64_hunt",
            "deob.powershell_decode",
            "deob.js_beautify",
            "misc.olevba_scan",
            "misc.mraptor_scan",
        ],
    },
    {
        "id": "decryption",
        "phases": ["Analyze"],
        "evidence": ["file"],
        "purpose": "Symmetrically decrypt an encrypted artifact once a key is known (AES CBC/ECB/CTR/GCM, RC4) — the actual decrypt step for ransomware/CTF/crypto cases, not just key discovery.",
        "tools": [
            "crypto.decrypt",
            "crypto.algorithms_supported",
        ],
    },
    {
        "id": "email_forensics",
        "phases": ["Triage", "Collect", "Analyze"],
        "evidence": ["file", "mounted_fs"],
        "purpose": "Parse phishing emails and mail stores: reconcile headers (From/Return-Path/Reply-To/Message-ID, SPF/DKIM/DMARC), enumerate senders/recipients, and hash attachments.",
        "tools": [
            "misc.parse_email",
            "misc.parse_msg_ole",
            "misc.parse_emlx",
            "misc.readpst_extract",
            "misc.pff_export",
        ],
    },
    {
        "id": "archive_extraction",
        "phases": ["Triage", "Collect"],
        "evidence": ["file"],
        "purpose": "Extract zip/tar/gz/7z/rar evidence archives — KAPE/triage collection bundles, zipped log exports, packed malware samples — before analysis. Zip Slip and zip-bomb guarded on the zip/tar/gz path.",
        "tools": [
            "archive.zip_extract",
            "archive.tar_extract",
            "archive.gzip_extract",
            "archive.archive_extract_7z",
            "archive.archive_extract_rar",
        ],
    },
    {
        "id": "image_steganography",
        "phases": ["Analyze"],
        "evidence": ["file"],
        "purpose": "Extract data hidden in carrier images (steghide, outguess and jphide embeddings) with a passphrase taken from the evidence; steg_status says which extractors are installed and what each reads.",
        "tools": [
            "steg.steg_extract",
            "steg.steg_status",
        ],
    },
    {
        "id": "image_content",
        "phases": ["Analyze"],
        "evidence": ["file"],
        "purpose": "Describe what a carved or exported picture shows (what is depicted, the visible text verbatim, the objects) with a vision-capable model; runs only when the case brief turns vision descriptions on.",
        "tools": [
            "images.describe",
        ],
    },
    {
        "id": "ioc_scan_enrichment",
        "phases": ["Scan", "Analyze"],
        "evidence": ["file", "memory", "pcap", "mounted_fs"],
        "purpose": "Sweep for known indicators and enrich hashes, IPs, and domains.",
        "tools": [
            "misc.knowns_pattern_generate",
            "yara.scan_file",
            "yara.scan_directory",
            "yara.scan_memory_image",
            "yara.scan_strings",
            "enrich.vt_lookup_hash",
            "enrich.vt_lookup_ip",
            "enrich.vt_lookup_domain",
            "enrich.vt_lookup_url",
            "enrich.urlscan_submit_scan",
            "enrich.urlscan_fetch_result",
            "enrich.abuseipdb_check",
            # Threat-intel context rather than a reputation verdict: OTX
            # pulses carry the malware-family and adversary labels the
            # attribution fusion reads, and passive DNS gives a domain's
            # historical resolutions. Omitted here originally, which left
            # them unreachable through capability-driven tool selection.
            "enrich.otx_lookup",
            "enrich.passive_dns",
            "enrich.urlscan_search",
            "enrich.misp_lookup",
            "enrich.whois_lookup",
            "enrich.oui_lookup",
        ],
    },
    {
        "id": "anti_forensics",
        "phases": ["Analyze", "Scan"],
        "evidence": ["disk", "memory"],
        "purpose": "Check for timestomping, log/journal clearing, Sysmon evasion, USN journal reset, prefetch deletion, hidden ADS payloads, and Linux history/log tampering.",
        "tools": [
            "af.af_timestomp_drift",
            "af.af_event_log_clear",
            "af.af_sysmon_evasion",
            "af.af_prefetch_deletion",
            "af.af_usn_journal_deleted",
            "af.af_ads_enumeration",
            "af.af_zone_identifier_read",
            "af.af_linux_history_tampering",
            "af.af_linux_log_tampering",
        ],
    },
    {
        "id": "live_endpoint",
        "phases": ["Triage", "Collect", "Analyze", "Scan"],
        "evidence": ["live"],
        "purpose": "Read-only live endpoint enumeration through fixed SSH argv wrappers.",
        "tools": [
            "live.live_hosts",
            "live.live_processes",
            "live.live_process_details",
            "live.live_network_connections",
            "live.live_recent_logins",
            "live.live_services",
            "live.live_scheduled_tasks",
            "live.live_persistence_audit",
            "live.live_open_files",
            "live.live_read_file",
            "live.live_yara_scan",
        ],
    },
    {
        "id": "cross_artifact_correlation",
        "phases": ["Analyze", "Report"],
        "evidence": ["all"],
        "purpose": "Join process/file/network evidence, validate ATT&CK IDs, assess coverage, and attribute observed TTPs.",
        "tools": [
            "correlate.process_to_file",
            "correlate.network_to_process",
            "correlate.mitre_map",
            "correlate.mitre_validate",
            "correlate.killchain_timeline",
            "correlate.cross_source_reconciliation",
            "coverage.coverage_report",
            "attribution.attribute_actors",
        ],
    },
]


_SUBSTITUTIONS: list[dict] = [
    {
        "when": "pcap_only",
        "avoid_prefixes": ["vol.", "ez.", "tsk."],
        "prefer_capabilities": ["network_pcap", "ioc_scan_enrichment"],
        "note": "Use net.* extraction/search tools instead of memory, filesystem, or Windows artifact parsers.",
    },
    {
        "when": "disk_only",
        "avoid_prefixes": ["net.tcpdump_", "net.ngrep_search", "vol."],
        "prefer_capabilities": ["disk_filesystem_timeline", "windows_registry_identity", "windows_event_logs"],
        "note": "Use tsk.*, ez.*, misc.*, strings.*, hash.*, and yara.* over packet or memory tools.",
    },
    {
        "when": "memory_only",
        "avoid_prefixes": ["ez.", "tsk.", "plaso."],
        "prefer_capabilities": ["memory_process_network", "static_file_triage", "ioc_scan_enrichment"],
        "note": "Use vol.* memory wrappers and dump/extract files before disk-artifact parsers.",
    },
    {
        "when": "live_endpoint",
        "avoid_prefixes": ["vol.", "ez.", "tsk."],
        "prefer_capabilities": ["live_endpoint"],
        "note": "Use live.* read-only wrappers unless a collected image/artifact is explicitly available.",
    },
]


def _active_capabilities() -> list[dict]:
    """A copy of the capability table, so no caller can change the shared one."""
    return copy.deepcopy(_CAPABILITIES)


def tool_capability_manifest() -> dict:
    """Return a copy of the structured manifest (runtime-filtered)."""
    return {
        "version": MANIFEST_VERSION,
        "capabilities": _active_capabilities(),
        "substitutions": copy.deepcopy(_SUBSTITUTIONS),
    }


def allowed_tool_names() -> set[str]:
    """Return every tool ID that DAIR/reasoning may place in priority_tools."""
    names: set[str] = set()
    for cap in _active_capabilities():
        names.update(cap.get("tools", []))
    return names


def reconcile_manifest_with_runtime(
    runtime_aliases: set[str] | None = None,
    *,
    resolve=None,
) -> dict:
    """Reconcile the curated planning manifest against the live MCP surface.

    The capability manifest is intentionally smaller than the full MCP tool
    set (~planning vocabulary vs. every wrapper). Count inequality alone is
    therefore **not** a defect. A defect is a manifest ID that the runtime
    cannot resolve — that would let DAIR prescribe an uncallable tool.

    Provide either ``runtime_aliases`` (set of playbook-style dotted names)
    or a ``resolve(name) -> mcp_name|None`` callable (e.g. Toolbox.resolve).
    When both are omitted, the in-process Toolbox is consulted.
    """
    manifest = sorted(allowed_tool_names())
    if resolve is None and runtime_aliases is None:
        from agent.toolbox import Toolbox
        tb = Toolbox()
        resolve = tb.resolve
        runtime_aliases = {t.alias for t in tb.tools.values()}
    runtime_aliases = set(runtime_aliases or ())

    missing: list[str] = []
    resolved: list[str] = []
    for name in manifest:
        ok = False
        if resolve is not None and resolve(name) is not None:
            ok = True
        elif name in runtime_aliases:
            ok = True
        if ok:
            resolved.append(name)
        else:
            missing.append(name)

    return {
        "manifest_version": MANIFEST_VERSION,
        "manifest_count": len(manifest),
        "runtime_alias_count": len(runtime_aliases),
        "resolved_count": len(resolved),
        "missing_from_runtime": missing,
        # Explicit: curated subset vs full surface is by design.
        "count_gap_by_design": True,
        "ok": not missing,
    }


def capability_for_tool(tool_name: str) -> str:
    """Return the capability id for a tool, or an empty string if unknown."""
    for cap in _active_capabilities():
        if tool_name in cap.get("tools", []):
            return cap["id"]
    return ""


def unknown_priority_tools(priority_tools: list[str] | None) -> list[str]:
    """Return priority tool names not present in the manifest."""
    allowed = allowed_tool_names()
    return [t for t in (priority_tools or []) if isinstance(t, str) and t not in allowed]


def annotate_directives_with_manifest(directives: dict) -> dict:
    """Add manifest metadata to directives without changing the work order."""
    out = copy.deepcopy(directives)
    priority_tools = list(out.get("priority_tools") or [])
    out["priority_tools"] = priority_tools
    out["tool_manifest_version"] = MANIFEST_VERSION
    out["unknown_priority_tools"] = unknown_priority_tools(priority_tools)
    out["priority_tool_capabilities"] = [
        {"tool": t, "capability": capability_for_tool(t)}
        for t in priority_tools
        if isinstance(t, str)
    ]
    return out


# Always surface these in the DAIR/reason prompt even when a capability's
# tool list is truncated — close-out must not disappear from the director's
# vocabulary (write_projected past the 8-tool cut once produced a "not in
# manifest" hallucination).
_CLOSEOUT_TOOLS_ALWAYS = (
    "misc.write_projected_final_report",
    "misc.write_final_report",
    "misc.export_execution_log",
    "coverage.ledger_status",
    "coverage.mark_blocked",
    "reason.synthesize",
    "reason.pre_report_check",
    "claim.record_recommendation",
)


def format_tool_manifest_for_prompt(max_tools_per_capability: int = 8) -> str:
    """Compact text block for model system prompts."""
    caps = _active_capabilities()
    try:
        _gone = unavailable_tools()
    except Exception:  # noqa: BLE001
        _gone = {}
    lines = [
        "TOOL CAPABILITY MANIFEST:",
        f"- version: {MANIFEST_VERSION}",
        "- Use only these tool IDs in directives.priority_tools and challenge_method.",
        "- Select by capability/evidence type, then choose the smallest executable batch.",
        "- Close-out (always available): " + ", ".join(_CLOSEOUT_TOOLS_ALWAYS),
    ]
    for cap in caps:
        tools = list(cap["tools"][:max_tools_per_capability])
        # Pin close-out tools that belong to this capability even past the cut.
        for t in cap["tools"][max_tools_per_capability:]:
            if t in _CLOSEOUT_TOOLS_ALWAYS and t not in tools:
                tools.append(t)
        if len(cap["tools"]) > max_tools_per_capability:
            tools = tools + ["..."]
        shown = [f"{t} (not installed)" if t in _gone else t for t in tools]
        lines.append(
            f"- {cap['id']} | phases={','.join(cap['phases'])} | "
            f"evidence={','.join(cap['evidence'])} | tools={', '.join(shown)}"
        )
    lines.append("Evidence-type substitution rules:")
    for rule in _SUBSTITUTIONS:
        lines.append(
            f"- {rule['when']}: avoid {', '.join(rule['avoid_prefixes'])}; "
            f"prefer {', '.join(rule['prefer_capabilities'])}. {rule['note']}"
        )
    return "\n".join(lines)



# External programs the tool namespaces shell out to. Used for a warning at
# run start: a missing program costs the model a turn when it meets it, so
# the operator hears about it first. Nothing is hidden on this basis.
EXTERNAL_BINARIES: dict[str, tuple[str, ...]] = {
    "tsk": ("fls", "icat", "mmls", "istat"),
    "img": ("qemu-img",),
    "ez": ("dotnet",),
    "vol": ("vol",),
    "strings": ("strings",),
    "net": ("tshark", "tcpdump"),
    "plaso": ("log2timeline.py",),
    "ewf": ("ewfmount", "ewfinfo", "ewfverify"),
    "misc.regripper_hive": ("rip.pl",),
    "misc.regripper_list_plugins": ("rip.pl",),
    # Advertised for years with a hardcoded /usr/local/bin path and no
    # registry entry, so the manifest called them available on a machine
    # that had never installed them: the model spent a call each to find out.
    "misc.hindsight_chrome": ("hindsight.py|hindsight",),
    "steg.steg_extract": ("steghide|outguess|jpseek",),
    "ese.esedb_export": ("esedbexport",),
    "ese.esedb_info": ("esedbinfo",),
    "evt.evt_export": ("evtexport",),
    "velo": ("velociraptor",),
    "misc.pdfid_scan": ("pdfid.py|pdfid",),
    "misc.pdf_parser_analyze": ("pdf-parser.py|pdf-parser",),
    "misc.pe_carver": ("pe-carver",),
    # Every remaining program a tool can execute. Undeclared meant the
    # manifest advertised the tool and the model learned it was missing by
    # spending a call on it; tests/tools/test_program_declarations.py keeps
    # this list honest as tools are added.
    "img.vshadow_mount": ("vshadowmount",),
    "img.bde_mount": ("bdemount",),
    "img.bde_info": ("bdeinfo",),
    "tsk.tsk_indxparse": ("INDXParse.py",),
    "hash.hashdeep_compute": ("hashdeep",),
    "hash.hashdeep_audit": ("hashdeep",),
    "net.ngrep_search": ("ngrep",),
    "net.zeek_analyze": ("zeek",),
    "net.suricata_analyze": ("suricata",),
    "net.tcpxtract_streams": ("tcpxtract",),
    "enrich.machinae_lookup": ("machinae",),
    "bin.binwalk_scan": ("binwalk",),
    "bin.binwalk_extract": ("binwalk",),
    "bin.diec_scan": ("die|diec",),
    "bin.r2_summary": ("rz-bin|r2",),
    "bin.upx_detect": ("upx",),
    "bin.upx_unpack": ("upx",),
    "misc.clamscan_file": ("clamscan",),
    "misc.clamscan_directory": ("clamscan",),
    "misc.pff_export": ("pffexport",),
    "misc.readpst_extract": ("readpst",),
    "archive.archive_extract_rar": ("unrar",),
    "misc.chainsaw_hunt": ("chainsaw",),
    "misc.mft_rule_hunt": ("chainsaw",),
    "misc.analyzemft_parse": ("analyzemft",),
    "misc.batch_run": ("sqlite3",),
    "misc.capa_analyze": ("capa",),
    "misc.densityscout_scan": ("densityscout",),
    "misc.olevba_scan": ("olevba",),
    "misc.mraptor_scan": ("mraptor",),
    "misc.usnparser_parse": ("usn.py|usnparser",),
    "strings.floss_extract": ("floss",),
    "strings.strings_exiftool_metadata": ("exiftool",),
    "hash.hash_ssdeep_hash": ("ssdeep",),
    "carve.carve_bulk_extractor_scan": ("bulk_extractor",),
    "carve.carve_foremost_carve": ("foremost",),
    "carve.carve_scalpel_carve": ("scalpel",),
    "img.img_photorec_carve": ("photorec",),
}
# Python modules a namespace or tool imports instead of a program.
EXTERNAL_MODULES: dict[str, tuple[str, ...]] = {
    "yara": ("yara",),
    "misc.pe_scanner": ("pefile",),
    # python-evtx: read in process (core.evtx_reader) — its console scripts
    # are broken in the distribution, so the module is the dependency.
    "misc.evtx_dump": ("Evtx",),
    "misc.evtx_filter": ("Evtx",),
    # Pillow: the picture decoder tools/images_decode.py runs in its own process.
    "images": ("PIL",),
}
# Namespaces whose program lives in a managed home rather than on PATH:
# the wrapper module's own resolver decides (module, function, description).
AVAILABILITY_PROBES: dict[str, tuple[str, str, str]] = {
    "hayabusa": ("tools.hayabusa", "_binary", "hayabusa release under ~/.local/share/atlas/hayabusa"),
    # The vision role, resolved by the same function the tool uses, so the
    # mark and the tool agree; a "no ..." description is shown as it is.
    "images": ("tools.images", "_configured",
               "no vision model configured (set VISION_BACKEND to a registered provider whose model takes "
               "images, and VISION_MODEL for the id)"),
}


def missing_probed() -> list[tuple[str, str]]:
    """``(namespace_or_tool, what)`` for every probed install that is absent."""
    import importlib
    out = []
    for key, (module, func, what) in AVAILABILITY_PROBES.items():
        try:
            found = getattr(importlib.import_module(module), func)()
        except Exception:  # noqa: BLE001
            found = None
        if not found:
            out.append((key, what))
    return out


def _manifest_names() -> set[str]:
    names: set[str] = set()
    for cap in _CAPABILITIES:
        names.update(t for t in cap.get("tools", []) if not t.endswith((".", "_")))
    return names


def missing_modules() -> list[tuple[str, str]]:
    """``(namespace_or_tool, module)`` for every required module not importable."""
    import importlib.util
    return [(ns, m) for ns, mods in EXTERNAL_MODULES.items() for m in mods
            if importlib.util.find_spec(m) is None]


def unavailable_tools() -> dict[str, str]:
    """``{dotted tool: what is missing}`` for manifest tools whose program or
    module is absent on this host. Nothing is hidden: the prompt manifest
    marks them, so the director does not prescribe a tool that cannot run."""
    out: dict[str, str] = {}
    missing = [(k, b, "program") for k, b in missing_binaries()] + \
              [(k, m, "module") for k, m in missing_modules()] + \
              [(k, w, "install") for k, w in missing_probed()]
    if missing:
        for tool in sorted(_manifest_names()):
            ns = tool.split(".", 1)[0]
            for key, what, kind in missing:
                if key == tool or ("." not in key and key == ns):
                    # A probe that states its own sentence ("no ... configured")
                    # is shown as it is: a missing configuration is no install.
                    out.setdefault(tool, what if what.startswith("no ") else f"{kind} {what} not installed")
    # A reader the bound case's brief withholds (meta["case_switch"], the
    # consent row) is unavailable for that case: every reader list, the
    # availability marks and the manifest route through here, so no line
    # offers a read the case refuses.
    try:
        from core.execution_log import log
        case_dir = log.case_dir()
    except Exception:  # noqa: BLE001 - no bound case: nothing is withheld
        case_dir = None
    if case_dir:
        for tool in consent_withheld(None, case_dir):
            out.setdefault(tool, "withheld for this case: its consent row in the brief is off")
    return out


def missing_binaries() -> list[tuple[str, str]]:
    """``(namespace, program)`` for every advertised program not installed.

    Resolved through ``core.paths.tool_program`` — the same lookup the
    wrappers use. Asking PATH here while a wrapper hardcoded
    ``/usr/local/bin/<name>`` let the manifest and the tool disagree about
    what exists.
    """
    from core.paths import tool_program
    out: list[tuple[str, str]] = []
    for ns, bins in EXTERNAL_BINARIES.items():
        for spec in bins:
            # "a|b" means the tool accepts either program: several wrappers
            # prefer one and fall back to the other (rizin then radare2,
            # pdfid.py then pdfid). Marking such a tool unavailable because
            # the preferred name is absent hides a tool that works.
            alternatives = [a for a in str(spec).split("|") if a]
            if any(tool_program(a) for a in alternatives):
                continue
            out.append((ns, " or ".join(alternatives)))
    return out


# ── Readers by input format (capability wiring, derived from the registry) ──
#
# Which tool parses which input format is read from the tools' own
# signatures: a reader names its input by the parameter it declares for it
# (``evtx_path``, ``hive_path``, ``prefetch_path``, ``hives_dir``...). No
# list of artefacts or formats is kept here; a tool registered with a new
# input parameter adds its format to the block by itself. Generic input
# names (a file, a path, a directory, an image) say nothing about the format
# and are left out.
_GENERIC_INPUT_PARAMS = frozenset({
    "file_path", "path", "file", "directory", "dir_path", "target", "target_path", "image", "image_path",
    "evidence_path", "dump_file", "mount_root", "case_dir", "input_path", "source_path", "artifact_path",
    "storage_file",
})
_INPUT_PARAM_RE = re.compile(r"^(?!output)[a-z0-9_]+_(?:path|dir|file|hive|db|journal)$")


def input_format_param(schema: dict) -> str:
    """The parameter a tool's schema declares for its input format: the
    first required parameter (else the first parameter) shaped like a path
    to a named kind of input, or "" for a tool that names none."""
    props = list((schema or {}).get("properties") or {})
    required = [p for p in (schema or {}).get("required") or [] if p in props]
    for name in required + [p for p in props if p not in required]:
        if name.startswith("output"):
            continue
        if name in _GENERIC_INPUT_PARAMS:
            return ""            # the input is any file: no format declared
        if _INPUT_PARAM_RE.match(name) or name.endswith("_hive"):
            return name
    return ""


# Inputs that are Atlas's own material, not evidence: detection rules, a
# hash manifest, the ATT&CK reference table, a ground truth. A tool whose
# input is one of these reads no evidence format. (The parameter names of
# Atlas's own tools: wiring, not analysis.)
_OWN_MATERIAL_PARAMS = frozenset({"rules_path", "manifest_path", "table_path", "ground_truth_path",
                                  "hash_db_path", "recovery_key_path", "link_dir"})
# The grader's namespace is never a reader: a ground truth stays out of the run.
_NOT_READER_NAMESPACES = frozenset({"accuracy"})


def _dotted(name: str) -> str:
    parts = name.split("_")
    if len(parts) >= 2 and parts[0] == parts[1]:
        return f"{parts[0]}.{'_'.join(parts[2:])}"
    if len(parts) >= 2:
        return f"{parts[0]}.{'_'.join(parts[1:])}"
    return name


def _gloss(label: str, param: str, schema: dict, description: str) -> str:
    """A short one-word format label (a parameter stem such as j, rfc or
    db) gets the words that say what it is: the parameter's description,
    else the tool's first sentence, without a leading verb or article; no
    gloss when those words only repeat the label."""
    if " " in label or len(label) > 6:
        return label
    from core.tool_text import model_description
    body, sch = model_description(description, schema)
    pdesc = str(((sch.get("properties") or {}).get(param) or {}).get("description") or "")
    source = pdesc or body.split("\n\n")[0].replace("\n", " ")
    words = re.split(r"\.\s|;|,\s(?=[a-z])(?!etc\b)|\s[-\u2014]\s|\(|:\s", source)[0]
    words = re.sub(r"(?i)^\s*(?:parse|read|list|run|export|extract|summarise|quick triage of)"
                   r"(?:\s+and\s+\w+)?\s+", "", words)
    words = re.sub(r"(?i)^\s*(?:path to |the path of |path of )?(?:an? |the |single |one )*", "", words)
    # The gloss is the leading noun phrase: it ends before the first word that
    # opens a further phrase, so it never stops mid-phrase; a phrase longer
    # than a gloss should be gives no gloss at all rather than a cut one.
    words = re.split(r"(?i)\s(?:to|of|that|which|using|with|from|into|for|or|and|by|via|in|on|as)\s",
                     f" {words} ")[0].strip().rstrip(".,")
    if not words or len(words.split()) > 6 or words.casefold().strip(".$ ") == label.casefold():
        return label
    return f"{label} ({words})"


def _declared(entry: tuple) -> list[str]:
    """The media types a tool's registration declares it reads
    (``meta["reads"]``, tools.media_types), [] when it declares none."""
    meta = entry[3] if len(entry) > 3 and isinstance(entry[3], dict) else {}
    reads = meta.get("reads") or []
    return [str(t) for t in reads] if isinstance(reads, (list, tuple)) else []


def is_media_label(label: str) -> bool:
    """Whether a table label is a declared media type (``image/jpeg``) rather
    than a parameter's format name: a parameter name never holds a slash."""
    return "/" in str(label).split(" (", 1)[0]


# {builder: (the tools list it was built from, its value)}: the tables the
# class and input routes read per member name are built once per registry
# (registered_tool_schemas hands out one list per process; a test's own
# list is built for as long as it is the same object).
_TABLES: dict[str, tuple[Any, Any]] = {}


def _memo(name: str, tools: Any, build: Callable[[], Any]) -> Any:
    hit = _TABLES.get(name)
    if hit is not None and hit[0] is tools:
        return hit[1]
    value = build()
    _TABLES[name] = (tools, value)
    return value


def readers_by_format(tools: list[tuple]) -> dict[str, list[str]]:
    """``{format: [tool, ...]}`` from ``(tool name, input schema[,
    description[, meta]])`` entries: reading tools only (core.work_order
    .is_reading_tool), never the grader, never a tool over Atlas's own
    material. Two sources, both the tool's own registration: the input
    parameter's name without its path suffix (a folder input marked as
    such, glossed when the name alone says nothing), and the media types
    the tool declares it reads (``meta["reads"]``, one label per type). A
    tool with a generic parameter and no declaration reads no format."""
    return {k: list(v) for k, v in _memo("by_format", tools, lambda: _readers_by_format(tools)).items()}


def _readers_by_format(tools: list[tuple]) -> dict[str, list[str]]:
    from core.work_order import is_reading_tool
    raw: dict[str, list[tuple]] = {}
    media: dict[str, list[str]] = {}
    for entry in tools:
        name, schema = entry[0], entry[1]
        description = entry[2] if len(entry) > 2 else ""
        if name.split("_", 1)[0] in _NOT_READER_NAMESPACES or not is_reading_tool(name):
            continue
        for t in _declared(entry):
            media.setdefault(t, []).append(_dotted(name))
        param = input_format_param(schema)
        if not param or param in _OWN_MATERIAL_PARAMS:
            continue
        label = re.sub(r"_(?:path|file)$", "", param)
        label = re.sub(r"_dir$", " (folder)", label).replace("_", " ")
        raw.setdefault(label, []).append((name, param, schema, description))
    out: dict[str, list[str]] = {}
    for label, members in raw.items():
        # One gloss per format: from the member whose parameter says most.
        name, param, schema, description = max(
            members, key=lambda m: len(str(((m[2].get("properties") or {}).get(m[1]) or {}).get("description")
                                           or "")))
        glossed = _gloss(label, param, schema, description)
        out[glossed] = list(dict.fromkeys(_dotted(m[0]) for m in members))
    for t, names in media.items():
        out[t] = list(dict.fromkeys(names))
    memory = _memory_readers(tools)
    if memory:
        out[MEMORY_FORMAT] = memory
    return dict(sorted(out.items()))


def input_name_declarations(tools: list[tuple] | None = None) -> list[tuple[str, tuple[str, ...]]]:
    """``[(dotted reader, its declared file-name patterns)]`` for every
    reading tool whose registration declares ``meta["input_names"]``: the
    names its input has in a filesystem listing (``*.pf``, ``NTUSER.DAT``,
    ``$MFT``), the tool's own input format, never a case's. The fourth
    declaration channel beside the parameter name and the media types: a
    name resolves a reader where no extension can (a hive, a journal, a
    browser store), and a reader that declares names is reached by them,
    not by an extension another kind of file shares."""
    tools = tools if tools is not None else registered_tool_schemas()
    return list(_memo("input_names", tools, lambda: _input_name_declarations(tools)))


def _input_name_declarations(tools: list[tuple]) -> list[tuple[str, tuple[str, ...]]]:
    from core.work_order import is_reading_tool
    out: list[tuple[str, tuple[str, ...]]] = []
    for entry in tools:
        name = entry[0]
        meta = entry[3] if len(entry) > 3 and isinstance(entry[3], dict) else {}
        names = tuple(str(n).casefold() for n in (meta.get("input_names") or ()) if str(n).strip())
        if names and name.split("_", 1)[0] not in _NOT_READER_NAMESPACES and is_reading_tool(name):
            out.append((_dotted(name), names))
    return out


_EXT_PATTERN_RE = re.compile(r"^\*\.[^*?\[\]/.]+$")      # one extension; "*.tar.gz" is matched whole
# {id(declarations): (the declarations, their matcher)}: a declaration list
# is matched against thousands of member names in one class route; the
# matcher splits its patterns once (literal names, "*.ext" patterns, the
# rest) so a name costs two lookups and a handful of fnmatch calls.
_MATCHERS: dict[int, tuple[Any, tuple]] = {}


def _name_matcher(decl: list[tuple[str, tuple[str, ...]]]) -> tuple:
    hit = _MATCHERS.get(id(decl))
    if hit is not None and hit[0] is decl:
        return hit[1]
    literals: dict[str, list[str]] = {}
    by_ext: dict[str, list[str]] = {}
    rest: list[tuple[str, str]] = []
    for reader, pats in decl:
        for pat in pats:
            if not any(ch in pat for ch in "*?["):
                literals.setdefault(pat, []).append(reader)
            elif _EXT_PATTERN_RE.match(pat):
                by_ext.setdefault(pat[2:], []).append(reader)
            else:
                rest.append((reader, pat))
    matcher = (literals, by_ext, rest)
    if len(_MATCHERS) > 8:
        _MATCHERS.clear()
    _MATCHERS[id(decl)] = (decl, matcher)
    return matcher


def readers_by_input_name(name: str, declarations: list[tuple[str, tuple[str, ...]]] | None = None) -> list[str]:
    """The dotted readers whose declared input names (input_name_declarations)
    the file name matches: its base name against each pattern, case
    folded, shell-style (``*`` and ``?``), each reader once in declaration
    order."""
    base = str(name or "").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].casefold()
    if not base:
        return []
    decl = declarations if declarations is not None else input_name_declarations()
    literals, by_ext, rest = _name_matcher(decl)
    found = set(literals.get(base) or ())
    if "." in base[1:]:
        found.update(by_ext.get(base.rsplit(".", 1)[-1]) or ())
    found.update(r for r, pat in rest if fnmatch.fnmatchcase(base, pat))
    return [r for r, _pats in decl if r in found]


def metadata_only(tools: list[tuple] | None = None) -> set[str]:
    """The dotted readers whose declaration says they read a file's metadata,
    not its content (``meta["depth"] == "metadata"``): data for the gloss
    beside their name, never an order."""
    tools = tools if tools is not None else registered_tool_schemas()
    return {_dotted(e[0]) for e in tools
            if len(e) > 3 and isinstance(e[3], dict) and e[3].get("depth") == "metadata"}


def is_installed(tool: str, gone: set[str] | None = None) -> bool:
    """Whether a reader's program and module are here, by the availability
    marks (_not_installed). The marks spell a tool ``ns.<server name>`` and
    the table ``ns.<name>`` (_dotted), so both sides are brought to the listed
    name (core.coverage_ledger.listed_tool_name) before comparing; a
    namespace mark (``ns:<namespace>``) takes every tool of it."""
    from core.coverage_ledger import listed_tool_name
    gone = _not_installed() if gone is None else gone
    name = listed_tool_name(tool)
    if f"ns:{name.split('_', 1)[0]}" in gone:
        return False
    return name not in {listed_tool_name(g) for g in gone if not g.startswith("ns:")}


def declared_readers_for_extension(ext: str, tools: list[tuple] | None = None) -> list[str]:
    """The declared readers of the media type a file extension names
    (tools.media_types.EXTENSIONS), installed or not; [] for an extension
    outside the table."""
    from tools.media_types import EXTENSIONS
    t = EXTENSIONS.get(str(ext or "").lower().lstrip("."), "")
    if not t:
        return []
    tools = tools if tools is not None else registered_tool_schemas()
    return _media_readers([t], readers_by_format(tools), tools)


def _media_readers(types: list[str], table: dict[str, list[str]], tools: list[tuple]) -> list[str]:
    """The readers of every declared type one of ``types`` matches, each
    once, in the tools' registration order (the table's own order is by
    label)."""
    from tools.media_types import matches
    order = {_dotted(e[0]): i for i, e in enumerate(tools)}
    names = [n for label, ns in table.items() if is_media_label(label) and matches([label], types) for n in ns]
    return sorted(dict.fromkeys(names), key=lambda n: order.get(n, len(order)))


def consent_withheld(tools: list[tuple] | None, case_dir) -> set[str]:
    """The dotted tools whose declared case switch (``meta["case_switch"]``,
    core.case_config.case_switch) is off for ``case_dir``: withheld from the
    readers a line names and from the readers a leave counts, since a read
    the case refuses is no read on offer. {} without a case."""
    if not case_dir:
        return set()
    if tools is None:
        # Never force the registry here: the server imports this module
        # while it registers its tools, and the availability marks are read
        # during that import (a forced build would wait on itself). The
        # callers that line up readers pass the registry; the marks and the
        # manifest follow once it exists.
        tools = _REGISTERED or []
    out: set[str] = set()
    switches: dict[str, bool] = {}
    for entry in tools:
        meta = entry[3] if len(entry) > 3 and isinstance(entry[3], dict) else {}
        name = str(meta.get("case_switch") or "")
        if not name:
            continue
        if name not in switches:
            try:
                from core.case_config import case_switch
                switches[name] = bool(case_switch(case_dir, name))
            except Exception:  # noqa: BLE001 - an unreadable switch is off
                switches[name] = False
        if not switches[name]:
            out.add(_dotted(entry[0]))
    return out


def withheld_tools(case_dir, tools: list[tuple] | None = None) -> set[str]:
    """The availability marks (the spelling of _not_installed) of the tools
    the case or the operator chose not to run: a reader withheld by the
    case's consent row, and a namespace whose availability probe reports a
    missing configuration ("no ... configured"), not a missing install. A
    leave of an extracted class leaves these out of the declared readers;
    a missing program or module still blocks it."""
    out: set[str] = set()
    try:
        out |= consent_withheld(tools, case_dir)
    except Exception:  # noqa: BLE001
        pass
    try:
        out |= {f"ns:{k}" for k, what in missing_probed() if str(what).startswith("no ")}
    except Exception:  # noqa: BLE001
        pass
    return out


def readers_of_type(media_type: str, tools: list[tuple] | None = None, *,
                    table: dict[str, list[str]] | None = None, gone: set[str] | None = None,
                    installed: bool = True) -> list[str]:
    """The readers that declare ``media_type`` (an exact type or one an
    ``image/*``-style declaration takes), dotted, in registration order; []
    when none declares it. ``installed`` True keeps the ones whose program
    and module are here; False gives the declared set as it is. What the
    leave of an extracted class reads (core.coverage_ledger._class_left):
    every declared reader must be here and have failed."""
    if not media_type:
        return []
    tools = tools if tools is not None else registered_tool_schemas()
    table = readers_by_format(tools) if table is None else table
    declared = _media_readers([media_type], table, tools)
    if not installed:
        return declared
    gone = _not_installed() if gone is None else gone
    return [r for r in declared if is_installed(r, gone)]


def class_readers(path: str, tools: list[tuple] | None = None, limit: int = 3, *,
                  table: dict[str, list[str]] | None = None, gone: set[str] | None = None,
                  meta: set[str] | None = None) -> list[tuple[str, bool]]:
    """The installed readers that take the file at ``path`` (by content when it
    is on disk, by name otherwise), as ``(listed name, metadata only)``, at
    most ``limit``: first one per namespace in registration order (a
    namespace is one toolkit, so the line reaches a third toolkit before it
    repeats one), then the rest in registration order while room is left (a
    plain .gz names tar_extract and gzip_extract both). What a line that
    offers a read of the file names beside it. ``table``, ``gone`` and
    ``meta`` may be passed by a caller that lines up many files, so they are
    computed once, not per file."""
    from core.coverage_ledger import listed_tool_name
    _label, readers = readers_for_input(path, tools, table=table, gone=gone)
    meta = metadata_only(tools) if meta is None else meta
    first: list[str] = []
    seen: set[str] = set()
    for r in readers:
        ns = r.split(".", 1)[0]
        if ns not in seen and len(first) < limit:
            seen.add(ns)
            first.append(r)
    picked = first + [r for r in readers if r not in first][:max(0, limit - len(first))]
    return [(listed_tool_name(r), r in meta) for r in picked]


def text_readers(tools: list[tuple] | None = None) -> list[str]:
    """The readers of plain text (core.artifact_value.TEXT_FORMATS): the
    generic text tools. Kept out of readers_by_format, whose block tells
    the analyst that a text search does not parse a format; a text file
    has nothing else to parse it."""
    from core.work_order import is_reading_tool
    tools = tools if tools is not None else registered_tool_schemas()
    return list(_memo("text", tools, lambda: list(dict.fromkeys(
        _dotted(e[0]) for e in tools if is_generic_text_tool(e[0]) and is_reading_tool(e[0])))))


MEMORY_FORMAT = "memory image"
# The input parameter names a memory plugin takes its image by: generic
# names, so the parameter rule above cannot class them.
_IMAGE_PARAMS = ("image", "memory_image")


def _memory_readers(tools: list[tuple]) -> list[str]:
    """The memory format's readers: reading tools that take an image and
    whose name is a plugin of one of the memory structures
    (core.evidence_disposition.MEMORY_STRUCTURES, the public plugin
    vocabulary that credits a memory image's classes). Capability, never
    a choice of what to look for."""
    from core.evidence_disposition import MEMORY_STRUCTURES
    from core.work_order import is_reading_tool
    plugins = sorted({p for ps in MEMORY_STRUCTURES.values() for p in ps}, key=len, reverse=True)
    out = []
    for entry in tools:
        name, schema = entry[0], entry[1]
        props = (schema or {}).get("properties") or {}
        if not any(p in props for p in _IMAGE_PARAMS) or not is_reading_tool(name):
            continue
        base = name.lower()
        if any(re.search(rf"(?<![a-z]){p}(?![a-z])", base) for p in plugins):
            out.append(_dotted(name))
    return list(dict.fromkeys(out))


def _not_installed() -> set[str]:
    """The dotted tools whose program or module is missing here (the
    availability data the manifest already marks)."""
    try:
        gone = set(unavailable_tools())
        missing = [k for k, _b in missing_binaries()] + [k for k, _m in missing_modules()] + \
                  [k for k, _w in missing_probed()]
        return gone | {f"ns:{k}" for k in missing if "." not in k} | {k for k in missing if "." in k}
    except Exception:  # noqa: BLE001
        return set()


_REGISTERED: list[tuple[str, dict]] | None = None


def registered_tool_schemas() -> list[tuple[str, dict]]:
    """``(name, input schema, description, meta)`` of every tool the server
    registers, read once per process (in a thread of its own, so a caller
    inside the server's event loop can read it too); ``meta`` is what the
    registration declared (``reads``, ``depth``), {} when nothing."""
    global _REGISTERED
    if _REGISTERED is None:
        import asyncio
        import concurrent.futures
        import inspect

        def _list():
            r = server.mcp.list_tools()
            tools = asyncio.run(r) if inspect.isawaitable(r) else r
            return [(t.name, dict(getattr(t, "parameters", None) or {}), str(t.description or ""),
                     dict(getattr(t, "meta", None) or {}))
                    for t in tools]
        try:
            # Imported here, in the calling thread: importing the tools asks
            # the trace log for its case, and a caller that holds the log's
            # lock (the work order's matcher) would wait on its own worker.
            import server
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                _REGISTERED = ex.submit(_list).result(timeout=60)
        except Exception:  # noqa: BLE001 - no registry, no block
            return []
    return _REGISTERED


def readers_by_format_on() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_READERS_BY_FORMAT", True)


def readers_block(tools: list[tuple[str, dict]] | None = None) -> str:
    """The "readers by input format" lines for the director's block and the
    analyst's tool guidance (ATLAS_READERS_BY_FORMAT); "" when off."""
    if not readers_by_format_on():
        return ""
    tools = tools if tools is not None else registered_tool_schemas()
    table = readers_by_format(tools)
    if not table:
        return ""
    gone = _not_installed()
    meta = metadata_only(tools)

    def shown(tool: str) -> str:
        gloss = " (metadata only)" if tool in meta else ""
        return f"{tool}{gloss} (not installed)" if not is_installed(tool, gone) else f"{tool}{gloss}"
    formats = {k: v for k, v in table.items() if not is_media_label(k)}
    lines: list[str] = []
    if formats:
        lines.append("READERS BY INPUT FORMAT (each parses its format; a byte or text search over such a file "
                     "does not parse it):")
        lines += [f"- {fmt}: {', '.join(shown(t) for t in names)}" for fmt, names in formats.items()]
    # The declared media types, one line per set of readers (a reader of
    # every image is one line, not one per type).
    from tools.media_types import CANONICAL
    by_readers: dict[tuple[str, ...], list[str]] = {}
    for label, names in table.items():
        if is_media_label(label):
            shown_label = CANONICAL.get(label, label)      # one spelling per type family
            labels = by_readers.setdefault(tuple(names), [])
            if shown_label not in labels:
                labels.append(shown_label)
    if by_readers:
        lines.append("READERS BY CONTENT TYPE (each reads its type, found by content or by name; a strings pass "
                     "over such a file is a read of its own, a text read of it is not):")
        # A reader set of many types shows the first few and a count: the
        # class lines carry the readers per file, the block says what reads what.
        lines += [f"- {', '.join(labels[:_BLOCK_LABELS])}"
                  + (f" and {len(labels) - _BLOCK_LABELS} more types" if len(labels) > _BLOCK_LABELS else "")
                  + f": {', '.join(shown(t) for t in names)}"
                  for names, labels in by_readers.items()]
    return "\n".join(lines)


_BLOCK_LABELS = 4



# ── routing an input to its format's readers ──────────────────────────────
#
# Capability routing, not investigative logic: which tool parses which
# input format is read from the registered readers' declared inputs
# (readers_by_format); nothing here says what to look for. A generic text
# tool (a strings pass, a text grep, a text read: universal tool-name
# shapes) over an input whose format has an installed reader reads the
# format's bytes as text and misses its structure, so it is refused with the
# readers named.

_GENERIC_TEXT_TOOL_RE = re.compile(r"(?:^|[._])(?:strings_grep|strings_extract|read_text)$")


def format_readers_on() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_FORMAT_READER_ROUTING", True)


def is_generic_text_tool(tool: str) -> bool:
    return bool(_GENERIC_TEXT_TOOL_RE.search(str(tool or "").replace(".", "_")))


def _format_names(label: str) -> tuple[str, set[str]]:
    """(head, the file names the gloss lists) of a readers-by-format label."""
    head = label.split(" (", 1)[0].strip().casefold()
    gloss = label.split(" (", 1)[1].rstrip(")") if " (" in label else ""
    names = {n.strip().casefold().rstrip(".") for n in gloss.split(",")} - {"", "etc", "folder"}
    return head, names


def readers_for_input(path: str, tools: list[tuple] | None = None,
                      index_class: Optional[Callable[[str], str]] = None, *,
                      table: dict[str, list[str]] | None = None,
                      gone: set[str] | None = None) -> tuple[str, list[str]]:
    """(format label, installed readers) of an input. In this order: by its
    extension against a parameter-declared format; by a file name the
    reader's format declares, or the folder it lies in, only when the
    contents index classes the input as an artefact (a recognised identity,
    not any file that happens to share a name); then by its media type
    (tools.media_types: the content when the file is on disk, else the
    name) against the declared types, the label being the type. ("", [])
    when no reader declares it."""
    p = str(path or "").replace("\\", "/").rstrip("/")
    base = p.rsplit("/", 1)[-1].casefold()
    parent = p.rsplit("/", 2)[-2].casefold() if p.count("/") >= 1 else ""
    ext = base.rsplit(".", 1)[-1] if "." in base else ""
    tools = tools if tools is not None else registered_tool_schemas()
    table = readers_by_format(tools) if table is None else table
    gone = _not_installed() if gone is None else gone

    def installed(readers: list[str]) -> list[str]:
        return [r for r in readers if is_installed(r, gone)]
    heads = [(label, *_format_names(label)) for label in table if not is_media_label(label)]
    for label, head, _names in heads:
        if " " not in head and ext and ext == head and installed(table[label]):
            return label, installed(table[label])
    by_name = [(label, head) for label, head, names in heads
               if " " not in head and (base in names or base == head or parent == head)]
    # A reader that declares the input's name (meta["input_names"]) is a
    # by-name candidate under its label, before the gloss names.
    named = set(readers_by_input_name(base, input_name_declarations(tools)))
    if named:
        by_name = [(label, head) for label, head, _names in heads
                   if named & set(table[label])] + [c for c in by_name if not (named & set(table[c[0]]))]
    if by_name:
        cls = (index_class or _index_class)(p)
        if cls:
            for label, _head in by_name:
                if installed(table[label]):
                    return label, installed(table[label])
    from tools.media_types import content_type, name_type
    # By content when the file is here (a carved file named by its carver,
    # a renamed payload), by name always (a handle, an inner path). Every
    # declaration the type matches counts, in the tools' registration order.
    types = list(dict.fromkeys(t for t in (content_type(_on_disk(path)), name_type(p)) if t))
    if types:
        readers = installed(_media_readers(types, table, tools))
        if readers:
            return types[0], readers
    return "", []


def _on_disk(path: str) -> str:
    """``path`` as a file here when it is one: as given, else resolved
    against the active case (a case-relative export); "" for a handle or an
    inner path (nothing to type by content)."""
    p = str(path or "")
    if not p or "::" in p:
        return ""
    if os.path.isfile(p):
        return p
    try:
        from core.paths import active_case_dir
        case = active_case_dir()
        full = os.path.join(str(case), p) if case and not os.path.isabs(p) else ""
        return full if full and os.path.isfile(full) else ""
    except Exception:  # noqa: BLE001
        return ""


def _index_class(path: str) -> str:
    """The contents index's class of the entry an input stands for ("" when
    unknown). Every input form is brought to the index's own key first: an
    image handle (image::inner path) to its inner path on that image; a
    path, absolute or relative, to its case-relative form for the copies
    an extraction registered; else an inner path, matched as a suffix."""
    try:
        from contextlib import closing
        from pathlib import Path
        from core.contents_index import _connect, _like_escape, _rel, handle_parts
        from core.paths import active_case_dir
        case = active_case_dir()
        con = _connect(case) if case else None
    except Exception:  # noqa: BLE001
        return ""
    if con is None:
        return ""
    raw = str(path).strip()
    parts = handle_parts(case, raw) if "::" in raw else None
    with closing(con):
        if parts:
            row = con.execute("SELECT class FROM entries WHERE origin = 'image' AND path = ? COLLATE NOCASE "
                              "AND (image = ? OR ? = '') AND class IS NOT NULL AND class != '' LIMIT 1",
                              (parts["inner_path"], parts["image"] if parts.get("matched") else "",
                               parts["image"] if parts.get("matched") else "")).fetchone()
            return str(row[0] or "") if row else ""
        try:
            rel = _rel(Path(case), raw).replace("\\", "/").strip("/")
        except Exception:  # noqa: BLE001
            rel = ""
        p = raw.replace("\\", "/").strip("/")
        row = None
        if rel:
            row = con.execute("SELECT e.class FROM copies c JOIN entries e ON e.id = c.entry_id "
                              "WHERE c.copy_path = ? COLLATE NOCASE LIMIT 1", (rel,)).fetchone()
        if not row:
            row = con.execute("SELECT e.class FROM copies c JOIN entries e ON e.id = c.entry_id "
                              "WHERE c.copy_path LIKE ? ESCAPE '\\' LIMIT 1", ("%" + _like_escape(p),)).fetchone()
        if not row:
            row = con.execute("SELECT class FROM entries WHERE origin = 'image' AND (path = ? COLLATE NOCASE "
                              "OR path LIKE ? ESCAPE '\\') AND class IS NOT NULL AND class != '' LIMIT 1",
                              (p, "%/" + _like_escape(p.rsplit("/", 3)[-1] if "/" not in p else p))).fetchone()
    return str(row[0] or "") if row else ""


# A search term with no pattern syntax (a word, a value, an identifier).
_LITERAL_RE = re.compile(r"^[^.*+?\[\](){}|^$\\]+$")


def _reader_ran_on(path: str, readers: list[str]) -> bool:
    """Whether a reader of the input's format already ran on it (a
    successful call naming its file)."""
    base = str(path).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    if not base:
        return False
    try:
        from core.execution_log import log
        entries = list(log._entries)
    except Exception:  # noqa: BLE001
        return False
    names = {r.replace(".", "_") for r in readers} | {r.split(".", 1)[-1] for r in readers}
    for e in entries:
        if e.get("type") != "tool_call" or e.get("success") is False:
            continue
        cmd = str(e.get("cmd") or "")
        tool = cmd.removeprefix("<py>:").split(" ", 1)[0]
        if (tool in names or any(tool.endswith(n) for n in names)) and base in cmd + str(e.get("args") or ""):
            return True
    return False


def generic_text_refusal(tool: str, path: str, tools: list[tuple] | None = None, pattern: str = "",
                         is_text: Optional[bool] = None) -> str:
    """Why a generic text tool may not read ``path`` ("" when it may).

    A parameter-declared format (a record format: a hive, an event log, a
    prefetch file) is read by its parser: a text search with a literal term
    is allowed once a reader of the format ran on the same input (it finds
    what the parser skips); a strings pass, any call before a reader ran,
    and a text read of a binary input stay refused.

    A declared media type (an image, a document, an archive, an executable)
    is also bytes worth a strings pass (embedded text, names, URLs), so only
    a text read of it is refused, and only when the input is a file here
    known not to be text: ``is_text`` is True, False or None (not known: a
    handle, an inner path, a planned read), and None is never refused by this
    rule. The parameter route decides first (readers_for_input)."""
    if not format_readers_on() or not is_generic_text_tool(tool):
        return ""
    label, readers = readers_for_input(path, tools)
    if not readers:
        return ""
    name = str(tool).replace(".", "_")
    if is_media_label(label):
        if name.endswith("read_text") and is_text is False and _on_disk(path):
            return (f"{tool} would decode {path.rsplit('/', 1)[-1] or path} as text, but it is not text: its "
                    f"content type ({label}) has installed readers: {', '.join(readers[:4])}; read it with one "
                    "of them; strings_extract and strings_grep stay allowed over it")
        return ""
    if name.endswith("read_text") and is_text:
        return ""
    if name.endswith("strings_grep") and pattern and _LITERAL_RE.match(str(pattern)) \
            and _reader_ran_on(path, readers):
        return ""
    return (f"{tool} would read {path.rsplit('/', 1)[-1] or path} as raw text, but its format ({label}) has "
            f"installed readers that parse it: {', '.join(readers[:4])}; parse it first; afterwards "
            "strings_grep with a term finds what the parser skips")
