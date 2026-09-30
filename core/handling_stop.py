"""A handling stop: material that must not be handled.

Once a brief or a recorded finding asserts a class whose material the
examiner is not permitted to copy (child sexual abuse material is the one
such class), every tool that would carve, extract, dump or render it is
refused, while metadata, context, attribution and timeline work continues.
The state is case-level, asserted automatically on an asserted reading, and
lifted only by a human who removes the file; the lifting is recorded.

Every tool has a class: allowed, refused (it writes copies of content across
a volume, a capture, an archive or a mailbox), media (a per-file tool refused
when the file's content is an image or a video, decided by its magic, never
by its extension alone) or online (a lookup or submission to an outside
service, refused while the stop stands because hashes of the material would
disclose the case). A test fails for a tool without a class.

In the subject frame (a seized device) the examination continues under the
gate. In the incident frame (a private examiner on an organisation's system)
the automated examination of the affected device ends at the assertion:
every call whose path arguments lie under that device's evidence or mounts is
refused as handed over, and the rest of the estate continues.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable

STOP_FILE = "HANDLING_STOP.json"
RECORD_FILE = "handling_stop_record.json"
STOP_CLASSES = ("csam",)

MEDIA_EXTENSIONS = frozenset({
    "jpg", "jpeg", "jpe", "jfif", "png", "gif", "bmp", "webp", "heic", "heif", "tif", "tiff", "psd", "avif",
    "mp4", "m4v", "mov", "avi", "mkv", "webm", "3gp", "wmv", "flv", "mpg", "mpeg", "mts", "ts",
})

REFUSED_TOOLS = frozenset((
    "archive_archive_extract_7z", "archive_archive_extract_rar", "archive_gzip_extract",
    "archive_tar_extract", "archive_zip_extract", "bin_binwalk_extract",
    "bin_upx_unpack", "carve_bulk_extractor_scan", "carve_bulk_extractor_unallocated",
    "carve_foremost_carve", "carve_scalpel_carve", "img_photorec_carve",
    "img_vmdk_export_raw", "job_job_start_bulk_extractor", "job_job_start_foremost_carve",
    "job_job_start_scalpel_carve", "misc_batch_run", "misc_pe_carver", "misc_pff_export",
    "misc_readpst_extract", "misc_symlink_evidence", "net_tcpdump_extract_http",
    "net_tcpdump_write_filtered", "net_tcpxtract_streams", "tsk_tsk_blkcat",
    "tsk_tsk_blkls", "tsk_tsk_jcat", "tsk_tsk_mmcat", "tsk_tsk_recover",
    "tsk_tsk_sorter", "steg_steg_extract", "velo_collect_artifact",
    "velo_get_collection_results", "velo_query", "velo_upload_artifact_yaml",
    "vol_vol_dumpfiles",
))
MEDIA_TOOLS = frozenset((
    "bin_binwalk_scan", "bin_diec_scan", "bin_r2_summary", "crypto_decrypt",
    "deob_base64_hunt", "deob_js_beautify", "deob_powershell_decode", "ez_ez_bstrings",
    "live_live_read_file", "misc_capa_analyze", "misc_parse_email", "misc_parse_emlx",
    "misc_parse_msg_ole", "misc_pdf_parser_analyze", "misc_pdfid_scan", "tsk_tsk_icat",
    "steg_steg_status", "strings_floss_extract", "strings_hexdump", "strings_read_text",
    "strings_strings_extract", "strings_xxd_dump",
))
ONLINE_TOOLS = frozenset((
    "enrich_abuseipdb_check", "enrich_enrichment_status", "enrich_machinae_lookup",
    "enrich_misp_lookup", "enrich_otx_lookup", "enrich_oui_lookup",
    "enrich_passive_dns", "enrich_urlscan_fetch_result", "enrich_urlscan_search",
    "enrich_urlscan_submit_scan", "enrich_vt_lookup_domain", "enrich_vt_lookup_hash",
    "enrich_vt_lookup_ip", "enrich_vt_lookup_url", "enrich_whois_lookup",
))
ALLOWED_TOOLS = frozenset((
    "accuracy_accuracy_compare", "accuracy_accuracy_export_report",
    "af_af_ads_enumeration", "af_af_event_log_clear",
    "af_af_linux_history_tampering", "af_af_linux_log_tampering",
    "af_af_prefetch_deletion", "af_af_sysmon_evasion",
    "af_af_timestomp_drift", "af_af_usn_gaps",
    "af_af_usn_journal_deleted", "af_af_zone_identifier_read",
    "attribution_attribute_actors", "bin_tlsh_compare", "bin_tlsh_hash",
    "bin_upx_detect", "brain_consult", "brain_search_notes", "carve_bulk_extractor_report",
    "claim_add_claim", "claim_add_conflict", "claim_add_hypothesis", "claim_add_indicators",
    "claim_add_observation", "claim_detect_contradictions", "claim_list_recommendations",
    "claim_promote_conclusion", "claim_record_recommendation", "claim_resolve_conflict",
    "claim_revalidate", "claim_snapshot", "claim_supersede", "claim_update_recommendation",
    "correlate_cross_source_reconciliation", "correlate_killchain_timeline", "correlate_mitre_map",
    "correlate_mitre_validate", "correlate_network_to_process", "correlate_process_to_file",
    "coverage_audit_evidence_coverage", "coverage_audit_hostile_auth_coverage",
    "coverage_audit_tool_coverage", "coverage_coverage_report", "coverage_ledger_status",
    "coverage_mark_blocked", "crypto_algorithms_supported", "dair_dair_assess",
    "deob_decode_chain", "deob_hex_decode", "deob_supported_ops", "deob_xor_bruteforce",
    "ese_esedb_export", "ese_esedb_info", "evt_evt_export", "ewf_ewf_info", "ewf_ewf_mount",
    "ewf_ewf_umount", "ewf_ewf_verify", "ewf_mount_full_image", "ewf_mount_ntfs",
    "ewf_umount_filesystem", "export_export_iocs", "export_export_navigator",
    "ez_ez_amcacheparser", "ez_ez_appcompatcacheparser", "ez_ez_evtxecmd",
    "ez_ez_jlecmd", "ez_ez_lecmd", "ez_ez_mftecmd", "ez_ez_mftecmd_dir", "ez_ez_mftecmd_usn",
    "ez_ez_sumecmd", "misc_onedrive_odl",
    "ez_ez_pecmd", "ez_ez_rbcmd", "ez_ez_recentfilecache", "ez_ez_recmd_batch",
    "ez_ez_recmd_dir", "ez_ez_recmd_hive", "ez_ez_rla", "ez_ez_sbecmd",
    "ez_ez_sqlecmd", "ez_ez_srumecmd", "ez_ez_wxtcmd", "hash_hash_directory",
    "hash_hash_file", "hash_hashdeep_audit", "hash_hashdeep_compute",
    "hash_md5deep_scan", "hash_ssdeep_compare", "hash_ssdeep_hash",
    "hash_ssdeep_scan_directory", "hash_verify_evidence_hash", "hayabusa_status",
    "hayabusa_summary", "hayabusa_triage", "img_bde_info", "img_bde_mount",
    "img_losetup_create", "img_losetup_detach", "img_losetup_list",
    "img_partprobe_refresh", "img_vmdk_chain_info", "img_vshadow_list",
    "img_vshadow_mount", "img_vshadow_umount", "img_xmount_image",
    "img_xmount_umount", "job_job_cancel", "job_job_collect", "job_job_list",
    "job_job_start_hayabusa", "job_job_start_plaso_targeted", "job_job_start_plaso_timeline",
    "job_job_status", "job_job_wait", "job_job_wait_all", "live_live_event_log_tail",
    "live_live_hosts", "live_live_network_connections", "live_live_open_files",
    "live_live_persistence_audit", "live_live_process_details", "live_live_processes",
    "live_live_recent_logins", "live_live_scheduled_tasks", "live_live_services",
    "live_live_users", "live_live_yara_scan", "misc_analyzemft_parse", "misc_chainsaw_hunt",
    "misc_clamscan_directory", "misc_clamscan_file", "misc_clear_case_run",
    "misc_current_investigation_state", "misc_densityscout_scan", "misc_device_install_inventory",
    "misc_evtx_dump", "misc_evtx_filter", "misc_export_execution_log", "misc_hindsight_chrome",
    "misc_inventory_evidence", "misc_knowns_pattern_generate", "misc_list_evidence_dir",
    "misc_list_investigation_tasks", "misc_mft_rule_hunt", "misc_mraptor_scan",
    "misc_olevba_scan",
    "misc_parse_scheduled_tasks", "misc_pe_scanner", "misc_record_agent_message",
    "misc_record_curiosity_probe", "misc_record_finding", "misc_record_self_correction",
    "misc_regripper_hive", "misc_regripper_list_plugins", "misc_serve_dashboard",
    "misc_start_execution_log", "misc_supersede_investigation_task",
    "misc_update_investigation_task", "misc_usnparser_parse", "misc_write_case_document",
    "misc_write_final_report", "misc_write_projected_final_report", "monitor_ack_alert",
    "monitor_baseline_capture", "monitor_check_alerts", "monitor_clear_awaiting_approval",
    "monitor_end_investigation", "monitor_extend_investigation", "monitor_get_response_state",
    "monitor_list_watchers", "monitor_next_investigation_id", "monitor_open_investigation_state",
    "monitor_set_awaiting_approval", "monitor_start_investigation", "monitor_start_watcher",
    "monitor_stop_watcher", "net_http_session_inventory", "net_ngrep_search",
    "net_pcap_identity_timeline", "net_suricata_analyze", "net_tcpdump_extract_dns",
    "net_tcpdump_extract_ips", "net_tcpdump_list_connections", "net_tcpdump_read",
    "net_tshark_conversations", "net_tshark_ja3", "net_tshark_protocol_hierarchy",
    "net_zeek_analyze", "plaso_plaso_create_targeted", "plaso_plaso_create_timeline",
    "plaso_plaso_export_csv", "plaso_plaso_export_json", "plaso_plaso_filter_incident_window",
    "plaso_plaso_info", "plaso_plaso_list_parsers", "reason_reason_audit_findings",
    "reason_reason_cite_check", "reason_reason_confidence_score",
    "reason_reason_evaluate_finding", "reason_reason_hypothesize", "reason_reason_plan",
    "reason_reason_pre_report_check", "reason_reason_synthesize", "respond_approve_action",
    "respond_execute_action", "respond_list_actions", "respond_revert_action",
    "respond_suggest_containment", "search_search_evidence", "search_search_index_status", "search_intel_sweep",
    "tsk_tsk_blkcalc", "tsk_tsk_blkstat", "tsk_tsk_ffind", "tsk_tsk_fls",
    "tsk_tsk_fsstat", "tsk_tsk_hfind", "tsk_tsk_ils", "tsk_tsk_indxparse",
    "tsk_tsk_istat", "tsk_tsk_jls", "tsk_tsk_mactime", "tsk_tsk_mmls",
    "tsk_tsk_mmstat", "tsk_tsk_resolve_path", "tsk_tsk_sigfind",
    "strings_exiftool_batch", "strings_exiftool_metadata", "strings_file_identify",
    "strings_file_identify_directory", "strings_stat_file", "strings_strings_grep",
    "table_table_grep", "table_table_pivot", "table_table_query", "table_table_schema",
    "velo_client_info", "velo_get_client_event_table", "velo_list_clients",
    "velo_update_client_event_table", "velo_wait_for_flow", "vol_vol_amcache",
    "vol_vol_cachedump", "vol_vol_callbacks", "vol_vol_cmdline",
    "vol_vol_cmdscanner", "vol_vol_consoles", "vol_vol_devicetree",
    "vol_vol_dlllist", "vol_vol_driverirp", "vol_vol_driverscan",
    "vol_vol_envars", "vol_vol_filescan", "vol_vol_getsids",
    "vol_vol_handles", "vol_vol_hashdump", "vol_vol_hollowprocesses",
    "vol_vol_info", "vol_vol_ldrmodules", "vol_vol_linux_check_modules",
    "vol_vol_linux_lsmod", "vol_vol_linux_lsof", "vol_vol_linux_malfind",
    "vol_vol_linux_netstat", "vol_vol_linux_pslist", "vol_vol_linux_psscan",
    "vol_vol_linux_pstree", "vol_vol_lsadump", "vol_vol_malfind",
    "vol_vol_memmap", "vol_vol_mftscan", "vol_vol_modscan",
    "vol_vol_modules", "vol_vol_mutantscan", "vol_vol_netscan",
    "vol_vol_netstat", "vol_vol_pebmasquerade", "vol_vol_privileges",
    "vol_vol_pslist", "vol_vol_psscan", "vol_vol_pstree",
    "vol_vol_psxview", "vol_vol_registry_amcache",
    "vol_vol_registry_hivelist", "vol_vol_registry_hivescan",
    "vol_vol_registry_printkey", "vol_vol_scheduled_tasks",
    "vol_vol_sessions", "vol_vol_shimcachemem", "vol_vol_ssdt",
    "vol_vol_suspicious_threads", "vol_vol_svcdiff", "vol_vol_svclist",
    "vol_vol_svcscan", "vol_vol_symbol_check", "vol_vol_symlinkscan",
    "vol_vol_thrdscan", "vol_vol_timeliner", "vol_vol_unhooked_system_calls",
    "vol_vol_userassist", "vol_vol_vadinfo", "vol_vol_vadwalk",
    "vol_vol_vadyarascan", "vol_vol_yarascan", "yara_yara_compile_check",
    "yara_yara_scan_directory", "yara_yara_scan_file", "yara_yara_scan_memory_image",
    "yara_yara_scan_process_memory", "yara_yara_scan_strings",
))
# Tools that record, reason or plan act on beliefs, not on the device: they
# keep running for a device handed over in the incident frame.
_BOOKKEEPING_PREFIXES = ("misc_record_", "misc_update_investigation_task", "misc_write_", "misc_start_execution_log",
                         "claim_", "reason_", "coverage_", "dair_", "respond_", "monitor_",
                         "export_", "accuracy_", "brain_", "correlate_")
# Mail parsers write attachments to disk through this argument: refused
# under the stop, while the parse of headers and bodies stays media-gated.
_ATTACHMENT_ARGS = ("extract_attachments_to",)


def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stop_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir) / STOP_FILE


def record_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir) / ".atlas" / RECORD_FILE


def _read(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def tool_class(name: str) -> str | None:
    """allowed, refused, media, online, or None for a tool without a class."""
    if name in REFUSED_TOOLS:
        return "refused"
    if name in MEDIA_TOOLS:
        return "media"
    if name in ONLINE_TOOLS:
        return "online"
    if name in ALLOWED_TOOLS:
        return "allowed"
    return None


# ── state ────────────────────────────────────────────────────────────────

MIRROR_MARKER = "mirror_of.json"


def mirrored_case(case_dir: str | os.PathLike) -> Path | None:
    """The real case an ``--output-dir`` mirror stands for
    (``<mirror>/.atlas/mirror_of.json``), or None."""
    data = _read(Path(case_dir) / ".atlas" / MIRROR_MARKER) or {}
    real = str(data.get("real_case") or "")
    if not real or not Path(real).is_dir():
        return None
    try:
        if Path(real).resolve() == Path(case_dir).resolve():
            return None
    except OSError:
        return None
    return Path(real)


def assert_stop(case_dir: str | os.PathLike, cls: str, basis: str, *, frame: str = "",
                device: str = "") -> dict[str, Any]:
    """Assert the stop once; a second assertion returns the first. Asserted
    in a mirror, it stands in the real case as well: the evidence is the
    same, and a later run of the real case must not handle it again."""
    real = mirrored_case(case_dir)
    if real is not None:
        _assert_here(real, cls, basis, frame=frame, device=device)
    return _assert_here(case_dir, cls, basis, frame=frame, device=device)


def _assert_here(case_dir: str | os.PathLike, cls: str, basis: str, *, frame: str = "",
                 device: str = "") -> dict[str, Any]:
    existing = _read(stop_path(case_dir))
    if existing:
        return existing
    if not frame:
        try:
            from core.indicators import frame_for
            frame = frame_for(case_dir)
        except Exception:  # noqa: BLE001
            frame = "incident"
    state = {"class": cls, "asserted_at": _utcnow(), "basis": basis, "frame": frame,
             "device": device if frame == "incident" else "", "refused": []}
    _write(stop_path(case_dir), state)
    _write(record_path(case_dir), {**state, "lifted_at": ""})
    return state


def state(case_dir: str | os.PathLike | None) -> dict[str, Any] | None:
    """The standing stop, or None. A record without its root file means a
    human lifted the stop: the lifting time is written once."""
    if not case_dir:
        return None
    current = _read(stop_path(case_dir))
    if current:
        return current
    rec = _read(record_path(case_dir))
    if rec and not rec.get("lifted_at"):
        rec["lifted_at"] = _utcnow()
        _write(record_path(case_dir), rec)
    return None


def record(case_dir: str | os.PathLike | None) -> dict[str, Any] | None:
    """The assertion record, standing or lifted, for the report."""
    if not case_dir:
        return None
    state(case_dir)
    return _read(record_path(case_dir)) or _read(stop_path(case_dir))


def is_stopped(case_dir: str | os.PathLike | None) -> bool:
    return state(case_dir) is not None


def note_refusal(case_dir: str | os.PathLike, tool: str, reason: str) -> None:
    current = _read(stop_path(case_dir))
    if not current:
        return
    current.setdefault("refused", []).append({"tool": tool, "at": _utcnow(), "reason": reason[:200]})
    current["refused"] = current["refused"][-500:]
    _write(stop_path(case_dir), current)
    rec = _read(record_path(case_dir))
    if rec is not None:
        rec["refused_count"] = len(current["refused"])
        _write(record_path(case_dir), rec)


# ── content checks ───────────────────────────────────────────────────────

def _mime_of_bytes(data: bytes) -> str:
    try:
        out = subprocess.run(["file", "-b", "--mime-type", "-"], input=data, capture_output=True, timeout=10)
        return out.stdout.decode("utf-8", "replace").strip().lower()
    except (OSError, subprocess.SubprocessError):
        return ""


def _mime_of_path(path: Path) -> str:
    try:
        out = subprocess.run(["file", "-b", "--mime-type", str(path)], capture_output=True, timeout=10)
        return out.stdout.decode("utf-8", "replace").strip().lower()
    except (OSError, subprocess.SubprocessError):
        return ""


def is_media_mime(mime: str) -> bool:
    return mime.startswith("image/") or mime.startswith("video/")


def path_is_media(path: str | os.PathLike) -> bool:
    """Whether a file holds an image or a video: its magic decides; an
    extension only adds a refusal for a file that is not there to read."""
    p = Path(str(path))
    if p.is_file():
        mime = _mime_of_path(p)
        if mime:
            return is_media_mime(mime)
    return p.suffix.lower().lstrip(".") in MEDIA_EXTENSIONS


def _icat_head(image: str, inode: str, offset_sectors: int | None = None) -> bytes:
    """The first bytes of an inode through icat: read-only, nothing kept."""
    cmd = ["icat"]
    if offset_sectors:
        cmd += ["-o", str(offset_sectors)]
    cmd += [str(image), str(inode)]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            head = proc.stdout.read(4096) if proc.stdout else b""
        finally:
            proc.kill()
            proc.wait(timeout=10)
        return head
    except (OSError, subprocess.SubprocessError):
        return b""


def inode_is_media(image: str, inode: str, offset_sectors: int | None = None) -> bool:
    """Peek at the first bytes of an inode and decide by their magic. A peek
    that returns nothing (an unreadable image, a missing icat) fails closed."""
    head = _icat_head(image, inode, offset_sectors)
    if not head:
        return True
    return is_media_mime(_mime_of_bytes(head))


def _text_is_media(values: Iterable[str]) -> bool:
    """Whether a tool's printed strings carry an image or a video: a
    string's first bytes, or the bytes behind a long base64 run in it, by
    their magic."""
    import base64
    for text in values:
        if not text:
            continue
        head = text[:4096].encode("latin-1", "ignore")
        if head and is_media_mime(_mime_of_bytes(head)):
            return True
        for run in re.findall(r"[A-Za-z0-9+/]{64,}={0,2}", text[:200_000])[:20]:
            try:
                raw = base64.b64decode(run[:5464] + "=" * (-len(run[:5464]) % 4), validate=False)
            except Exception:  # noqa: BLE001
                continue
            if raw and is_media_mime(_mime_of_bytes(raw[:4096])):
                return True
    return False


def _result_strings(result: Any) -> list[str]:
    """Every string a tool result carries, unescaped: the values of its
    dict, or of the JSON its content items print."""
    out: list[str] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, str):
            out.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                walk(v)

    content = getattr(result, "content", None)
    if isinstance(content, (list, tuple)):
        for item in content:
            text = getattr(item, "text", None)
            if isinstance(text, str):
                try:
                    walk(json.loads(text))
                except ValueError:
                    out.append(text)
    else:
        walk(result)
    return out


# ── the device handed over (incident frame) ──────────────────────────────

def device_paths(case_dir: str | os.PathLike, device: str) -> list[str]:
    """The evidence paths and mount points of one device: its evidence
    entries (label or host), and the mount plan's volumes of those images.
    With no device, or a device that matches no entry, every evidence path
    and mount point: all evidence is handed over."""
    key = (device or "").casefold()
    if key:
        found = _device_roots(case_dir, key)
        if found:
            return found
    return _device_roots(case_dir, "")


def _device_roots(case_dir: str | os.PathLike, key: str) -> list[str]:
    out: list[str] = []
    images: set[str] = set()
    try:
        from core.evidence_links import load_evidence_links
        for e in (load_evidence_links(case_dir).get("entries") or []):
            if not isinstance(e, dict):
                continue
            if not key or str(e.get("label") or "").casefold() == key or str(e.get("host") or "").casefold() == key:
                p = str(e.get("path") or "").strip()
                if p:
                    out.append(p); images.add(os.path.normpath(p))
    except Exception:  # noqa: BLE001
        pass
    try:
        from core.mount_plan import load_mount_plan
        plan = load_mount_plan(case_dir) or {}
        for vol in (plan.get("volumes") or plan.get("images") or []):
            if not isinstance(vol, dict):
                continue
            img = os.path.normpath(str(vol.get("image") or vol.get("path") or ""))
            stem = str(vol.get("stem") or "").casefold()
            if not key or img in images or (stem and stem == key):
                for k in ("mount_point", "ntfs_mount", "fs_mount", "root"):
                    mp = str(vol.get(k) or "").strip()
                    if mp:
                        out.append(mp)
    except Exception:  # noqa: BLE001
        pass
    root = Path(case_dir).resolve()
    if not key:
        for name in ("evidence", "mnt"):
            if (root / name).is_dir():
                out.append(str(root / name))
    resolved = []
    for p in out:
        pp = Path(p)
        resolved.append(str((root / pp).resolve() if not pp.is_absolute() else pp.resolve()))
    return sorted(set(resolved))


def _string_args(args: Any) -> Iterable[str]:
    if isinstance(args, str):
        yield args
    elif isinstance(args, dict):
        for v in args.values():
            yield from _string_args(v)
    elif isinstance(args, (list, tuple)):
        for v in args:
            yield from _string_args(v)


def _under(path: str, roots: list[str]) -> bool:
    try:
        p = Path(path).resolve()
    except (OSError, RuntimeError):
        return False
    for r in roots:
        try:
            if p == Path(r) or Path(r) in p.parents:
                return True
        except (OSError, RuntimeError):
            continue
    return False


# ── the gate ─────────────────────────────────────────────────────────────

def gate(tool_name: str, args: dict[str, Any], case_dir: str | os.PathLike | None) -> str | None:
    """The reason to refuse the call under a standing stop, or None."""
    st = state(case_dir)
    if not st:
        return None
    cls = tool_class(tool_name)
    tail = (f" A handling stop for {st['class']} material stands since {st['asserted_at']} (basis {st['basis']}); "
            "metadata, timeline, attribution and single-file hashing continue; the material goes to the human examiner.")
    reason = None
    # The stop file and its record are a human's: no tool names them.
    for value in _string_args(args):
        if os.path.basename(value.rstrip("/\\")) in (STOP_FILE, RECORD_FILE):
            reason = f"Tool {tool_name} refused: it names {os.path.basename(value)}, which only a human may touch."
            break
    if reason is None and any(args.get(k) for k in _ATTACHMENT_ARGS):
        reason = f"Tool {tool_name} refused: writing attachments to disk copies content, which the stop forbids."
    if reason is not None:
        pass
    elif cls is None:
        reason = f"Tool {tool_name} refused: it has no handling class and cannot run under a handling stop."
    elif cls == "refused":
        reason = f"Tool {tool_name} refused: it carves, extracts, copies or dumps content, which the stop forbids."
    elif cls == "online":
        reason = f"Tool {tool_name} refused: no online lookup or submission while the stop stands (hashes of the material would disclose the case)."
    elif cls == "media":
        if tool_name == "tsk_tsk_icat":
            if inode_is_media(str(args.get("image") or ""), str(args.get("inode") or ""), args.get("offset_sectors")):
                reason = f"Tool {tool_name} refused: the inode holds an image or a video."
        else:
            for value in _string_args(args):
                if len(value) < 3 or len(value) > 4096:
                    continue
                p = Path(value)
                if (p.is_file() or p.suffix) and path_is_media(p):
                    reason = f"Tool {tool_name} refused: {value[:120]} is an image or a video."
                    break
    if reason is None and st.get("frame") == "incident" and not tool_name.startswith(_BOOKKEEPING_PREFIXES):
        # The affected device is handed over; with no device on record, or
        # one that matches no evidence entry, all evidence is.
        roots = device_paths(case_dir, st.get("device") or "")
        whole = not st.get("device") or roots == _device_roots(case_dir, "")
        if roots:
            for value in _string_args(args):
                if len(value) < 2 or len(value) > 4096 or not (value.startswith("/") or Path(value).exists()):
                    continue
                if _under(value, roots):
                    what = "all evidence was" if whole else f"{st['device']} was"
                    reason = (f"Tool {tool_name} refused: {what} handed over at the assertion; the automated "
                              "examination of it ended" + ("." if whole else " and the rest of the estate continues."))
                    break
    if reason:
        note_refusal(case_dir, tool_name, reason)
        return reason + tail
    return None


def post_gate(tool_name: str, args: dict[str, Any], result: Any, case_dir: str | os.PathLike | None) -> str | None:
    """After a media-gated tool ran: the reason to withhold its result when
    the printed bytes, or the bytes behind a base64 run in them, are an
    image or a video (a live read, a decoder), or None."""
    st = state(case_dir)
    if not st or tool_class(tool_name) != "media":
        return None
    if _text_is_media(_result_strings(result)):
        reason = f"Tool {tool_name} refused: its output carries an image or a video, which the stop forbids to render."
        note_refusal(case_dir, tool_name, reason)
        return reason
    return None


def refuse_fresh_start(case_dir: str | os.PathLike | None) -> str | None:
    """Why a start without --resume is refused: it would wipe exports/,
    which hold copies that belong to the human examiner or the authority."""
    st = state(case_dir)
    if not st:
        return None
    return (f"a handling stop for {st['class']} material stands since {st['asserted_at']}: a fresh start would wipe "
            "exports/, which is quarantined for the human examiner. Start with --resume, or have the examiner lift "
            f"the stop by removing {STOP_FILE}.")


def dashboard_refuses(path: str | os.PathLike) -> bool:
    """Whether the dashboard's case-file route must answer 403 for a file
    under a case with a standing stop: anything under the quarantined
    exports/ folder, and an image or a video anywhere in the case."""
    p = Path(str(path))
    case_dir = None
    for parent in [p] + list(p.parents):
        if (parent / STOP_FILE).is_file():
            case_dir = parent
            break
    if case_dir is None:
        return False
    try:
        if (case_dir / "exports") in p.resolve().parents:
            return True
    except (OSError, RuntimeError):
        pass
    return path_is_media(p)


# ── what the analyst, the director and the report read ───────────────────

def prompt_block(case_dir: str | os.PathLike | None) -> str:
    st = state(case_dir)
    if not st:
        return ""
    lines = [f"# HANDLING STOP: {st['class']} material asserted at {st['asserted_at']} (basis {st['basis']})",
             "Tools that carve, extract, copy or dump content, per-file tools on an image or a video, and every "
             "online lookup are refused; nothing of the material is copied, rendered or hashed to an outside service. "
             "Continue with metadata, timeline, attribution and single-file hashes for the human examiner's hash-set "
             "match; do not prescribe a refused tool. The material goes to the human examiner."]
    if st.get("frame") == "incident":
        if st.get("device"):
            lines.append(f"The automated examination of {st['device']} ended at the assertion: it is preserved and "
                         "handed over; continue with the rest of the estate.")
        else:
            lines.append("The stop names no device: all evidence is handed over at the assertion; the automated "
                         "examination of it ended.")
    return "\n".join(lines) + "\n"


def report_lines(case_dir: str | os.PathLike | None, language: str = "en") -> list[str]:
    rec = record(case_dir)
    if not rec:
        return []
    de = language == "de"
    refused = int(rec.get("refused_count") or len(rec.get("refused") or []))
    lines = ["**Handling**" if not de else "**Umgang mit dem Material**"]
    if de:
        lines.append(f"- Umgangsstopp für {rec['class']}-Material, ausgelöst am {rec['asserted_at']} (Grundlage {rec['basis']})"
                     + (f", aufgehoben am {rec['lifted_at']}" if rec.get("lifted_at") else ", in Kraft") + ".")
        lines.append(f"- Nach der Auslösung wurde nichts von dem Material ausgeschnitten, exportiert, ausgegeben oder an "
                     f"einen externen Dienst gemeldet; {refused} Aufrufe wurden abgewiesen.")
        lines.append("- Vor der Auslösung geschriebene Exporte unter exports/ sind unter Quarantäne und gehen ungeöffnet an "
                     "die Prüferin oder den Prüfer.")
        if rec.get("frame") == "incident":
            lines.append(f"- Die automatisierte Untersuchung von {rec['device']} endete mit der Auslösung; das Gerät wurde "
                         "gesichert und übergeben." if rec.get("device") else
                         "- Der Stopp nennt kein Gerät: alle Beweismittel gelten seit der Auslösung als übergeben.")
    else:
        lines.append(f"- Handling stop for {rec['class']} material, asserted at {rec['asserted_at']} (basis {rec['basis']})"
                     + (f", lifted at {rec['lifted_at']}" if rec.get("lifted_at") else ", in force") + ".")
        lines.append(f"- After the assertion nothing of the material was carved, exported, dumped or submitted to an "
                     f"outside service; {refused} calls were refused.")
        lines.append("- Exports written before the assertion under exports/ are quarantined and go to the human examiner "
                     "unopened.")
        if rec.get("frame") == "incident":
            lines.append(f"- The automated examination of {rec['device']} ended at the assertion; the device was "
                         "preserved and handed over." if rec.get("device") else
                         "- The stop names no device: all evidence is handed over since the assertion.")
    return lines
