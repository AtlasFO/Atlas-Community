"""Curated Atlas tool capability manifest.

The manifest is intentionally small and semantic. It is not a full inventory of
every MCP wrapper; it is the planning vocabulary DAIR/reasoning should use when
choosing the next batch. Focused wrappers can still exist outside this list, but
priority_tools should come from these known, phase-appropriate capabilities.
"""
from __future__ import annotations

import copy


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
            "and timeline data. For VMDK evidence resolve the snapshot chain "
            "FIRST (img.vmdk_chain_info) — a base extent with snapshot "
            "deltas is frozen at snapshot creation; flatten via "
            "img.vmdk_export_raw, then open with tsk.mmls → tsk.fls "
            "(not loop/FUSE mounts as the Triage default)."
        ),
        "tools": [
            "img.vmdk_chain_info",
            "img.vmdk_export_raw",
            "tsk.mmls",
            "tsk.fls",
            "tsk.icat",
            "tsk.istat",
            "tsk.mactime",
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
}
# Namespaces whose program lives in a managed home rather than on PATH:
# the wrapper module's own resolver decides (module, function, description).
AVAILABILITY_PROBES: dict[str, tuple[str, str, str]] = {
    "hayabusa": ("tools.hayabusa", "_binary", "hayabusa release under ~/.local/share/atlas/hayabusa"),
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
    if not missing:
        return out
    for tool in sorted(_manifest_names()):
        ns = tool.split(".", 1)[0]
        for key, what, kind in missing:
            if key == tool or ("." not in key and key == ns):
                out.setdefault(tool, f"{kind} {what} not installed")
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
