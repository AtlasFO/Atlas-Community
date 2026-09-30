"""FastMCP middleware: trace every MCP tool call and enforce DAIR oversight."""
import asyncio
import json
import os
import re
import sys

from core.envfile import env_int
import time
import traceback

from fastmcp.exceptions import ToolError
from fastmcp.exceptions import ValidationError as FastMCPValidationError
from fastmcp.server.middleware import Middleware, MiddlewareContext
from mcp import types as mt
from pydantic import ValidationError as PydanticValidationError


# ── DAIR gate configuration ───────────────────────────────────────────────────

_SKIP_TOOLS = frozenset({"misc_record_agent_message", "misc_start_execution_log"})

DAIR_GATE_ALLOWLIST = frozenset({
    # Trace lifecycle
    "misc_start_execution_log",
    "misc_export_execution_log",
    # Close-out writers: projected report is the required path when beliefs
    # exist; freeform write_final_report remains for belief-less cases.
    # Omitting write_projected makes a run defer the only valid report tool,
    # and DAIR then calls it "not in the manifest".
    "misc_write_final_report",
    "misc_write_projected_final_report",
    "misc_record_agent_message",
    "misc_record_self_correction",
    # Recording a finding formalises evidence already gathered; the finding
    # gates require a recent dair_call on their own. Blocking it when the
    # window ages out only delays a finding the loop is asking for.
    "misc_record_finding",
    "misc_serve_dashboard",
    # Phase director itself
    "dair_assess",
    "dair_dair_assess",
    # Adversarial-review + scoring tools. These are META operations (they
    # reason ABOUT findings, they don't execute forensics on evidence), so
    # they must not independently require a fresh dair_assess in the window.
    # record_finding still carries the dair_required gate, so the investigation
    # as a whole stays DAIR-directed — but the per-finding review chain
    # (evaluate -> confidence -> cite) no longer ages the dair_call out of the
    # 20-entry window and forces a no-op re-engagement. Both the bare and
    # namespace-doubled registration forms are listed (cf. dair_assess above).
    "reason_plan", "reason_reason_plan",
    "reason_hypothesize", "reason_reason_hypothesize",
    "reason_evaluate_finding", "reason_reason_evaluate_finding",
    "reason_confidence_score", "reason_reason_confidence_score",
    "reason_cite_check", "reason_reason_cite_check",
    "reason_audit_findings", "reason_reason_audit_findings",
    "reason_synthesize", "reason_reason_synthesize",
    "reason_pre_report_check", "reason_reason_pre_report_check",
    "accuracy_compare", "accuracy_accuracy_compare",
    "accuracy_export_report", "accuracy_accuracy_export_report",
    "correlate_mitre_validate", "correlate_correlate_mitre_validate",
    "correlate_mitre_map", "correlate_correlate_mitre_map",
    "coverage_report", "coverage_coverage_report",
    # Pre-flight reads that run before the first dair_assess
    "hash_verify_evidence_hash",
    "vol_symbol_check",
    "vol_vol_symbol_check",
    # Evidence inventory latch — must run before forensic tools.
    "misc_inventory_evidence",
    "misc_list_evidence_dir",
    "misc_current_investigation_state",
    "misc_update_investigation_task",
    "strings_stat_file",
    # VMDK snapshot-chain resolution — a mandatory prep read for VMDK
    # evidence (playbook), and safe to run mid-investigation on a
    # newly-discovered disk. Descriptor/stat reads only, no evidence writes.
    "img_vmdk_chain_info",
    # claim_snapshot is meta (reads belief graph), not a forensic parse
    "claim_snapshot",
})

# Model actions (tool, reason, finding …) since the last dair_assess before
# forensic tools need a fresh assessment. Counted in actions, not raw trace
# entries — see ExecutionLog.ACTION_TYPES.
DAIR_WINDOW = env_int("ATLAS_DAIR_WINDOW", 20)


# ── Solution-material gate configuration ─────────────────────────────────────
# The accuracy grader legitimately reads the answer key to score a finished
# run; everything else is denied any argument that points into Solution/ or
# an answers file (see core.paths.is_solution_path).

SOLUTION_GATE_ALLOWLIST = frozenset({
    "accuracy_compare", "accuracy_accuracy_compare",
    "accuracy_export_report", "accuracy_accuracy_export_report",
})


# Argument keys that carry command/script text rather than prose. Only these
# get the substring scan (contains_solution_reference) on top of the
# path-shape check — a finding description that merely *mentions*
# ground_truth.json must never be blocked, but an interpreter payload like
# `python3 -c "open('ground_truth.json')"` is not path-shaped and would
# otherwise walk straight through the gate.
_COMMAND_KEYS = frozenset(
    {"cmd", "command", "script", "code", "expression", "query"})


def _find_solution_arg(value, key: str | None = None) -> str | None:
    """Depth-first scan of a tool-argument tree for a solution-material path."""
    from core.paths import contains_solution_reference, is_solution_path
    if isinstance(value, str):
        if is_solution_path(value):
            return value
        if key in _COMMAND_KEYS and contains_solution_reference(value):
            return value
        return None
    if isinstance(value, dict):
        for k, v in value.items():
            hit = _find_solution_arg(v, key=k if isinstance(k, str) else None)
            if hit:
                return hit
    elif isinstance(value, (list, tuple)):
        for v in value:
            # list items inherit the parent key: an argv list under "cmd" is
            # command material token by token
            hit = _find_solution_arg(v, key=key)
            if hit:
                return hit
    return None


# ── Case-relative path resolution ─────────────────────────────────────────────
# The MCP server's CWD is the repo root, not the case directory, so a relative
# mount_point / output_dir / output_path passed straight to subprocess/open()
# silently lands under the repo root.
# Every tool call passes through this middleware, so the rewrite happens here
# once instead of in ~40 tool wrappers.

def _allowed_input_roots(case_dir: str | None) -> list[str]:
    """Where a tool may read from: the case, attached evidence roots, the
    tool installation itself (rules, symbols, wrappers) and the temp dir.
    ``ATLAS_EVIDENCE_ROOTS`` (colon-separated) extends it per site."""
    import tempfile
    from core.paths import READ_ONLY_PREFIXES
    roots = [os.path.realpath(r.rstrip("/")) for r in READ_ONLY_PREFIXES]
    roots.append(os.path.realpath(tempfile.gettempdir()))
    roots.append(os.path.realpath(os.path.join(os.path.dirname(__file__), "..")))
    roots.append("/opt")
    if case_dir:
        roots.append(os.path.realpath(case_dir))
    for extra in os.environ.get("ATLAS_EVIDENCE_ROOTS", "").split(":"):
        if extra.strip():
            roots.append(os.path.realpath(extra.strip()))
    return roots


def _find_outside_case_arg(tool_name: str, args: dict) -> str | None:
    """The first existing absolute input path outside every allowed root."""
    from core.paths import CASE_PATH_PARAM_NAMES, INPUT_PATH_PARAM_NAMES
    names = set(INPUT_PATH_PARAM_NAMES) | set(CASE_PATH_PARAM_NAMES)
    if tool_name.endswith("start_execution_log"):
        return None
    try:
        from core.execution_log import log
        case_dir = log.case_dir()
    except Exception:
        case_dir = None
    roots = _allowed_input_roots(case_dir if isinstance(case_dir, str) else None)
    for k, v in (args or {}).items():
        if k not in names or not isinstance(v, str):
            continue
        cand = os.path.expanduser(v.strip())
        if not cand or not os.path.isabs(cand) or not os.path.exists(cand):
            continue
        real = os.path.realpath(cand)
        if not any(real == r or real.startswith(r + "/") for r in roots):
            return v.strip()
    return None


def _resolve_case_paths(tool_name: str, args: dict) -> dict | None:
    """Resolve relative case-path arguments against the active case directory.

    Returns a rewritten copy of `args`, or None when nothing needed rewriting.
    Raises ToolError when a relative path is given but no case directory is
    known — failing loudly beats silently writing into the server's CWD.
    """
    from core.paths import CASE_PATH_PARAM_NAMES
    rel = {
        k: v.strip() for k, v in args.items()
        if k in CASE_PATH_PARAM_NAMES and isinstance(v, str) and v.strip()
        and not os.path.isabs(os.path.expanduser(v.strip()))
    }
    if not rel:
        return None
    if tool_name.endswith("start_execution_log"):
        # The call that *establishes* the case dir: prefer an explicit absolute
        # case_dir argument. When atlas CLI has already chdir'd into the case
        # (cwd contains CASE.md / .atlas), allow relative analysis/… paths —
        # refusing them caused a permanent start_execution_log → regripper
        # "trace log not configured" cascade.
        base = str(args.get("case_dir") or "").strip()
        if base and os.path.isabs(os.path.expanduser(base)):
            base = os.path.abspath(os.path.expanduser(base))
        else:
            cwd = os.path.abspath(os.getcwd())
            if (os.path.isdir(os.path.join(cwd, ".atlas"))
                    or os.path.isfile(os.path.join(cwd, "CASE.md"))):
                base = cwd
            else:
                raise ToolError(
                    f"{tool_name}: output_path {rel.get('output_path')!r} is "
                    f"relative and would resolve against the MCP server's working "
                    f"directory ({os.getcwd()!r}), NOT the case directory. Pass an "
                    f"absolute output_path under <case_dir>/analysis/, or pass an "
                    f"absolute case_dir argument to resolve it against."
                )
    else:
        try:
            from core.execution_log import log
            base = log.case_dir()
        except Exception:
            base = None
        if not base:
            arg_list = ", ".join(f"{k}={v!r}" for k, v in rel.items())
            raise ToolError(
                f"{tool_name}: relative path argument(s) {arg_list} cannot be "
                f"resolved — no active case is configured, and the MCP "
                f"server's working directory ({os.getcwd()!r}) is not the "
                f"case directory. Call misc_start_execution_log first, or "
                f"pass absolute paths under the case directory."
            )
    resolved = dict(args)
    for k, v in rel.items():
        resolved[k] = os.path.normpath(os.path.join(base, v))
    return resolved


def _refuse_missing_input_paths(tool_name: str, args: dict) -> dict | None:
    """Discovery-first input-path gate.

    Missing paths are not "tool errors" to retry with another guess — they
    are protocol events: resolve via inventory/listing (or unique sibling
    rewrite), never invent basenames. Returns rewritten ``args`` when
    auto-resolved; raises ToolError with PROTOCOL_MARKER otherwise.
    """
    from core.deferred_intents import PROTOCOL_MARKER
    from core.discovery_first import check_and_resolve_input_paths

    case_dir = None
    try:
        from core.execution_log import log as _elog
        case_dir = _elog.case_dir()
    except Exception:
        case_dir = None

    try:
        new_args, resolutions = check_and_resolve_input_paths(
            tool_name, args, case_dir=case_dir)
    except ValueError as e:
        body = str(e)
        # Prefer structured JSON body when present
        msg = body
        try:
            data = json.loads(body)
            if isinstance(data, dict) and data.get("gate") == "discovery_first":
                msg = json.dumps(data, indent=2, ensure_ascii=False)
        except json.JSONDecodeError:
            pass
        raise ToolError(f"{PROTOCOL_MARKER} {msg}") from e

    if resolutions:
        try:
            from core.execution_log import log as _elog
            _elog._path_resolutions = getattr(_elog, "_path_resolutions", [])
            if isinstance(_elog._path_resolutions, list):
                _elog._path_resolutions.extend(resolutions)
        except Exception:
            pass
    return new_args


# ── MCP routing gate configuration ───────────────────────────────────────────

FORENSIC_BINARY_PATTERNS = (
    r"/usr/local/bin/vol\b",
    r"(?<![\w-])vol\.py\b",
    r"\bdotnet\s+\S*(?:MFTECmd|RECmd|EvtxECmd|PECmd|JLECmd|LECmd|SBECmd|"
    r"AmcacheParser|AppCompatCacheParser|WxTCmd|SQLECmd|RBCmd|RLA)\.dll",
    r"(?<![\w-])(?:fls|icat|istat|ils|blkls|mactime|tsk_recover|sigfind|"
    r"sorter|jls|jcat|mmls|fsstat|mmcat|mmstat|blkcalc|blkcat|blkstat|"
    r"ffind|hfind)\b",
    r"(?<![\w-])(?:hexdump|xxd|exiftool|ssdeep|hashdeep|md5deep)\b",
    r"(?<![\w-])(?:log2timeline\.py|psort\.py|pinfo\.py)\b",
    r"(?<![\w-])(?:yara|yarac|bulk_extractor|foremost|scalpel|photorec)\b",
    r"(?<![\w-])(?:ewfmount|ewfinfo|ewfverify|vshadowmount|bdemount|xmount)\b",
    r"(?<![\w-])tcpdump\b",
    r"(?<![\w-])clamscan\b",
    r"(?<![\w-])rip\.pl\b",
    # spreadsheet one-liners: python -c "import openpyxl…", xlsx2csv, csvkit
    r"(?<![\w-])(?:openpyxl|xlsx2csv|in2csv)\b",
)

MCP_WRAPPER_HINTS = {
    "vol": "vol.vol_* (e.g. vol.vol_pslist, vol.vol_netscan)",
    "RECmd": "ez.ez_recmd_hive / ez.ez_recmd_batch",
    "MFTECmd": "ez.ez_mftecmd",
    "EvtxECmd": "ez.ez_evtxecmd",
    "PECmd": "ez.ez_pecmd",
    "JLECmd": "ez.ez_jlecmd",
    "LECmd": "ez.ez_lecmd",
    "SBECmd": "ez.ez_sbecmd",
    "AmcacheParser": "ez.ez_amcacheparser",
    "AppCompatCacheParser": "ez.ez_appcompatcacheparser",
    "WxTCmd": "ez.ez_wxtcmd",
    "SQLECmd": "ez.ez_sqlecmd",
    "RBCmd": "ez.ez_rbcmd",
    "RLA": "ez.ez_rla",
    "fls": "tsk.tsk_fls",
    "icat": "tsk.tsk_icat",
    "istat": "tsk.tsk_istat",
    "ils": "tsk.tsk_ils",
    "blkls": "tsk.tsk_blkls",
    "mactime": "tsk.tsk_mactime",
    "tsk_recover": "tsk.tsk_recover",
    "sigfind": "tsk.tsk_sigfind",
    "sorter": "tsk.tsk_sorter",
    "jls": "tsk.tsk_jls",
    "jcat": "tsk.tsk_jcat",
    "mmls": "tsk.tsk_mmls",
    "fsstat": "tsk.tsk_fsstat",
    "hexdump": "strings.strings_hexdump",
    "xxd": "strings.strings_xxd_dump",
    "exiftool": "strings.strings_exiftool_metadata / strings.strings_exiftool_batch",
    "ssdeep": "hash.hash_ssdeep_hash / hash.hash_ssdeep_compare",
    "hashdeep": "hash.hash_hashdeep_compute / hash.hash_hashdeep_audit",
    "md5deep": "hash.hash_md5deep_scan",
    "log2timeline.py": "plaso.plaso_create_timeline / plaso.plaso_create_targeted",
    "psort.py": "plaso.plaso_export_csv / plaso.plaso_export_json / plaso.plaso_filter_incident_window",
    "pinfo.py": "plaso.plaso_info / plaso.plaso_list_parsers",
    "yara": "yara.yara_scan_file / yara.yara_scan_directory / yara.yara_scan_memory_image",
    "bulk_extractor": "carve.carve_bulk_extractor_scan",
    "foremost": "carve.carve_foremost_carve",
    "scalpel": "carve.carve_scalpel_carve",
    "photorec": "img.img_photorec_carve",
    "ewfmount": "ewf.ewf_ewf_mount / ewf.ewf_mount_full_image",
    "ewfinfo": "ewf.ewf_ewf_info",
    "ewfverify": "ewf.ewf_ewf_verify",
    "vshadowmount": "img.img_vshadow_mount",
    "bdemount": "img.img_bde_mount",
    "xmount": "img.img_xmount_image",
    "tcpdump": "net.net_tcpdump_read / net.net_tcpdump_extract_http / net.net_tcpdump_extract_dns",
    "clamscan": "misc.misc_clamscan_file / misc.misc_clamscan_directory",
    "rip.pl": "misc.misc_regripper_hive",
    "openpyxl": "table.table_schema / table.table_query (typed xlsx access)",
    "xlsx2csv": "table.table_schema / table.table_query",
    "in2csv": "table.table_schema / table.table_query",
}

# Binaries that are allowed through batch_run (no hard redirect — shell text
# processing is legitimate in small doses) but have a typed equivalent the
# enumeration cap steers to once they loop (raw fls, cat or strings calls
# repeated dozens of times): none of these verbs were in
# FORENSIC_BINARY_PATTERNS, so the routing redirect never saw the loops.
SOFT_WRAPPER_HINTS = {
    "strings": "strings.strings_extract / strings.strings_grep",
    "cat": "strings.strings_extract (text) / tsk.tsk_icat (by inode) / "
           "strings.hexdump (binary)",
    "head": "strings.strings_extract",
    "tail": "strings.strings_extract",
    "less": "strings.strings_extract",
    "more": "strings.strings_extract",
    "grep": "strings.strings_grep",
    "egrep": "strings.strings_grep",
    "zgrep": "strings.strings_grep",
    "file": "strings.file_identify / strings.file_identify_directory",
    "ls": "tsk.tsk_fls / ez.ez_mftecmd_dir",
    "find": "tsk.tsk_fls / ez.ez_mftecmd_dir",
    "dd": "tsk.tsk_blkcat / tsk.tsk_blkls",
    "stat": "strings.stat_file",
    "md5sum": "hash.hash_file",
    "sha1sum": "hash.hash_file",
    "sha256sum": "hash.hash_file",
}


def raw_tool_hint(bin_name: str) -> str:
    """Typed-tool alternative for a raw binary: hard-redirect wrappers first,
    then the soft (capped-but-allowed) map, else a generic pointer."""
    return (MCP_WRAPPER_HINTS.get(bin_name)
            or SOFT_WRAPPER_HINTS.get(bin_name)
            or "a typed tool namespace (strings.*, tsk.*, ez.*, hash.*) — "
               "check the tool listing for the equivalent")


def _identify_forensic_binary(cmd: str) -> str | None:
    import re
    if not cmd:
        return None
    for pat in FORENSIC_BINARY_PATTERNS:
        if not re.search(pat, cmd):
            continue
        for key in MCP_WRAPPER_HINTS:
            if key in cmd:
                return key
        return ""
    return None


# ── Gate helpers ──────────────────────────────────────────────────────────────

def dair_window_used(log=None) -> tuple[int, int]:
    """``(actions since the last dair_call, window size)``.

    Lets the loop warn the model a batch *before* the window ages out.
    Otherwise every window expiry costs two turns: a batch of refusals
    that become deferred intents, a bare dair_assess turn, then the same
    batch again. Before any dair_call nothing is counted (cold
    start is free), and with no dair_call in the window the gate is already
    refusing and its message carries the instruction.
    """
    try:
        if log is None:
            from core.execution_log import log as _log
            log = _log
        recent = log.recent_actions(DAIR_WINDOW)
        if not isinstance(recent, list):
            return 0, DAIR_WINDOW
    except Exception:  # noqa: BLE001
        return 0, DAIR_WINDOW
    from core.execution_log import action_key
    used: list[object] = []
    for e in reversed(recent):
        if e.get("type") == "dair_call":
            return len(used), DAIR_WINDOW
        k = action_key(e)
        if k not in used:
            used.append(k)
    return 0, DAIR_WINDOW


# A batch that begins inside the DAIR window runs to completion. The window
# used to be checked per call: a batch of eight with five actions of room lost
# three calls to deferred intents, then a bare dair_assess turn, then the same
# three calls again — a large share of the turns of a long run. The next batch
# still needs dair_assess first; nothing about the protocol moves except
# where the boundary falls. ATLAS_DAIR_BATCH_GRACE=0 restores per-call checks.
DAIR_BATCH_GRACE = env_int("ATLAS_DAIR_BATCH_GRACE", 1)
_batch_grace = False


def dair_window_open(log=None) -> bool:
    """A dair_call sits inside the recent-action window."""
    try:
        if log is None:
            from core.execution_log import log as _log
            log = _log
        recent = log.recent_actions(DAIR_WINDOW)
        return isinstance(recent, list) and any(e.get("type") == "dair_call" for e in recent)
    except Exception:  # noqa: BLE001
        return False


def begin_batch(log=None) -> bool:
    """Called by the loop when a turn's tool calls start; returns the grace."""
    global _batch_grace
    _batch_grace = bool(DAIR_BATCH_GRACE) and dair_window_open(log)
    return _batch_grace


def end_batch() -> None:
    global _batch_grace
    _batch_grace = False


def _gate_decision() -> tuple[bool, str]:
    """Return (should_block, reason). Fail-open on gate errors, but log them."""
    try:
        from core.execution_log import log
        entries = log._entries
        # Deferred backlog latch outranks the window check: forensic tools
        # stay blocked until dair_assess relieves the open queue.
        try:
            st = log.deferred_backlog_status()
            if st.get("latched"):
                return (
                    True,
                    f"deferred backlog full ({st['open']}/{st['cap']}; "
                    f"latch clears at ≤{st['hysteresis']} open)",
                )
        except Exception:
            pass
        if not entries:
            return False, "cold start (empty trace)"
        ever_dair = any(e.get("type") == "dair_call" for e in entries)
        if not ever_dair:
            return False, "cold start (DAIR not yet engaged)"
        if _batch_grace:
            return False, "batch began inside the DAIR window"
        recent = log.recent_actions(DAIR_WINDOW) if hasattr(log, "recent_actions") \
            else entries[-DAIR_WINDOW:]
        if not isinstance(recent, list):
            recent = entries[-DAIR_WINDOW:]
        recent_dair = any(e.get("type") == "dair_call" for e in recent)
        if recent_dair:
            return False, "active DAIR batch"
        return True, "DAIR engaged earlier but no dair_call in recent window"
    except Exception:
        tb = traceback.format_exc()
        print(f"[Atlas WARN] dair gate check failed (fail-open): {tb}", file=sys.stderr)
        try:
            from core.execution_log import log
            log.record_system_error("dair_gate", tb)
        except Exception as _e:
            print(f"[Atlas WARN] dair_gate system_error log failed: {_e}", file=sys.stderr)
        return False, "gate check error (fail-open)"


# ── Trace-write helpers ───────────────────────────────────────────────────────
# Centralised so the three outcome paths in on_call_tool stay readable.

def _trace_narration_failure(e: Exception, note: str) -> None:
    print(f"[Atlas WARN] narration logging failed: {e}", file=sys.stderr)
    try:
        from core.execution_log import log
        log.record_system_error(
            "narration",
            f"narration log failed: {e!r}\nnote={note[:200]}",
        )
    except Exception:
        pass


def _parent_cids() -> list[int] | None:
    """Return [log._last_dair_cid] if a dair_call has been recorded, else None.

    This is the prescribing DAIR entry for the current tool batch. Every
    tool_call, call_abandoned, and narration carries it as input_call_ids
    so the trace forms a proper causal DAG:
        dair_call → [tool_calls, narrations, call_abandoned, …] → findings
    """
    try:
        from core.execution_log import log
        cid = log._last_dair_cid
        return [cid] if cid else None
    except Exception:
        return None


def _trace_cancelled(tool_name: str, elapsed: float) -> None:
    try:
        from core.execution_log import log
        log.record_call_abandoned(
            tool_name,
            f"client cancellation after {elapsed}s — "
            f"check client tool-timeout or reduce work scope",
            input_call_ids=_parent_cids(),
        )
    except Exception as err:
        print(f"[Atlas FATAL] {tool_name} cancelled + trace-write failure: "
              f"{err!r}", file=sys.stderr, flush=True)


def _trace_exception(tool_name: str, exc: Exception, elapsed: float) -> None:
    tb = traceback.format_exc()
    try:
        from core.execution_log import log
        log.record_tool_call(
            cmd=f"<py>:{tool_name}",
            success=False,
            truncated=False,
            retries=0,
            exit_code=-1,
            stderr=f"Unhandled {type(exc).__name__} in {tool_name}:\n{tb}"[:4096],
            elapsed_seconds=elapsed,
            input_call_ids=_parent_cids(),
            failure_class="tool_error",
        )
    except Exception as log_err:
        print(
            f"[Atlas FATAL] tool exception + trace-write failure for "
            f"{tool_name}: original={exc!r}; trace_err={log_err!r}\n{tb}",
            file=sys.stderr, flush=True,
        )


def _validation_envelope(tool_name: str, exc: Exception) -> str:
    """Render an argument-validation error as a per-field listing.

    FastMCP validates tool arguments with a pydantic TypeAdapter before the
    tool body runs; the raw ValidationError otherwise escapes to the calling
    model as a truncated traceback that names no fields.
    """
    if isinstance(exc, PydanticValidationError):
        errors = exc.errors(include_url=False)
    else:  # fastmcp's own ValidationError carries only a message
        errors = [{"loc": (), "msg": str(exc)[:300],
                   "type": type(exc).__name__}]
    n = len(errors)
    lines = [f"{tool_name}: invalid arguments — {n} validation "
             f"error{'s' if n != 1 else ''}; the tool did not run."]
    for err in errors:
        field = ".".join(str(p) for p in err.get("loc", ())) or "<arguments>"
        line = f"  - {field}: {err.get('msg', 'invalid value')}"
        if err.get("type"):
            line += f" [{err['type']}]"
        if "input" in err:
            line += f"; received {repr(err['input'])[:120]}"
        lines.append(line)
    lines.append("Correct the listed fields and retry the same call.")
    return "\n".join(lines)


def _trace_validation_failure(tool_name: str, envelope: str,
                              elapsed: float) -> None:
    try:
        from core.execution_log import log
        log.record_tool_call(
            cmd=f"<py>:{tool_name}",
            success=False,
            truncated=False,
            retries=0,
            exit_code=-1,
            stderr=envelope,
            elapsed_seconds=elapsed,
            input_call_ids=_parent_cids(),
            failure_class="analyst_error",
        )
    except Exception as log_err:
        print(f"[Atlas FATAL] {tool_name} validation failure + trace-write "
              f"failure: {log_err!r}", file=sys.stderr, flush=True)


def _app_level_failure(result) -> tuple[str, str] | None:
    """Return (error text, failure_class) if the return payload reports failure.

    Tools that refuse at the application layer (gate refusals, validation
    errors) return `{"success": false, "error": ...}` as their result while
    the MCP call itself succeeds. Without inspecting the payload, the trace
    records such refusals as success:true and every trace consumer
    (run reviewer, stall detector, scorecards) over-counts successes.
    """
    try:
        payloads = []
        if isinstance(result, dict):
            payloads.append(result)
        else:
            sc = getattr(result, "structured_content", None)
            if isinstance(sc, dict):
                payloads.append(sc)
            content = getattr(result, "content", None)
            if content:
                import json
                for c in content:
                    text = getattr(c, "text", None)
                    if not text:
                        continue
                    try:
                        obj = json.loads(text)
                    except ValueError:
                        continue
                    if isinstance(obj, dict):
                        payloads.append(obj)
        for obj in payloads:
            if obj.get("success") is False:
                gate = obj.get("gate")
                msg = str(obj.get("error") or obj.get("stderr")
                          or "tool returned success: false")
                if gate:
                    return f"[{gate}] {msg}"[:512], "gate_refusal"
                # Preserve structured failure classes (sudo_auth, disk_floor,
                # …) — collapsing everything to tool_error hid privilege
                # failures from Access Stage / DAIR dampers.
                fc = str(obj.get("failure_class") or "").strip()
                if fc == "wrong_input_kind":
                    return msg[:512], "gate_refusal"
                if fc and fc not in ("tool_error",):
                    return msg[:512], fc
                return msg[:512], "tool_error"
    except Exception:
        return None
    return None


_EVIDENCE_REF_RE = re.compile(
    r"(?:^|/)(?:evidence|mnt)/[^\s]*|"                      # evidence/ or mnt/ paths
    r"[^\s]+\.(?:e01|raw|dd|img|vmdk|vhdx?|aff4?|001)$",    # bare image paths
    re.IGNORECASE,
)


def _extract_evidence_ref(args: dict) -> str:
    """Best-effort evidence reference from a tool call's arguments.

    Multi-host cases mount each image under its own path (mnt/host01, …); the
    trace needs to record which image/mount a call ran against so findings
    and tool calls can be attributed per host at report time. Purely a
    path-shape heuristic over string args — no per-wrapper changes.
    """
    for v in args.values():
        if not isinstance(v, str) or len(v) > 1024:
            continue
        m = _EVIDENCE_REF_RE.search(v)
        if m:
            return m.group(0)[:256]
    return ""


def _result_text(result) -> str:
    """The tool's result as text, for the trace excerpt and the spill."""
    payload = _result_payload(result)
    if payload:
        try:
            return json.dumps(payload, ensure_ascii=False, default=str)
        except Exception:  # noqa: BLE001
            return str(payload)
    if isinstance(result, str):
        return result
    parts = [getattr(c, "text", "") for c in (getattr(result, "content", None) or [])]
    return "\n".join(p for p in parts if p)


def _spill_result_text(text: str, tool_name: str) -> str:
    """Keep a Python tool's whole result on disk when the trace excerpt would
    cut it — the same retention subprocess output gets."""
    try:
        from core.executor import retain_output_text
        return retain_output_text(text, tool_name)
    except Exception:  # noqa: BLE001
        return ""


def _trace_success_baseline(tool_name: str, elapsed: float,
                             entries_before: int | None,
                             result=None, evidence_ref: str = "",
                             args: dict | None = None) -> None:
    """Write a baseline tool_call entry if the tool didn't self-log.

    Subprocess tools self-log via core.executor._log_tool. reason_*/dair_*
    self-log via record_reason_call/record_dair_call. Pure-Python tools
    (correlate_*, accuracy_*, etc.) don't — this baseline makes them visible.
    Self-logging is detected by whether log._entries grew during the call.
    The baseline reflects app-level failures reported in the return payload
    (see _app_level_failure) so gate refusals are visible in the trace.
    """
    if entries_before is None:
        return
    try:
        from core.execution_log import log
        # A tool that only commissioned reviews (record_finding running the
        # adversarial evaluation a CONFIRMED claim needs) has left no record
        # of its own call; the baseline is written for it as for a tool that
        # logged nothing. A reason or DAIR tool's reason_call is its own
        # record, as is any other kind of entry.
        added = list(log._entries[entries_before:])
        own_reviews = (not tool_name.startswith(("reason_", "dair_"))
                       and bool(added)
                       and all(e.get("type") == "reason_call" for e in added))
        if not added or own_reviews:
            failure = _app_level_failure(result)
            # The result text itself: without it the trace held only row
            # counts for table queries, and no finding quoting an address
            # or a time from one could ever be cited.
            text = _result_text(result)
            cid = log.record_tool_call(
                cmd=f"<py>:{tool_name}",
                success=failure is None,
                truncated=False,
                retries=0,
                exit_code=0 if failure is None else 1,
                stderr=failure[0] if failure else "",
                elapsed_seconds=elapsed,
                stdout_excerpt=text,
                input_call_ids=_parent_cids(),
                stdout_file=_spill_result_text(text, tool_name),
                failure_class=failure[1] if failure else "",
                evidence_ref=evidence_ref,
            )
            # How much of the result the caller could see: a finding that
            # generalises over "all rows" is checked against these counts
            # (tools/_gates/universal_from_truncated.py).
            meta = _result_meta(result)
            if meta and cid:
                log.annotate_tool_call(int(cid), result_meta=meta)
            # The arguments are what a later check needs to know what a
            # call was *about* (a grep for "winevt" is a winevt attempt).
            if cid and args:
                try:
                    log.annotate_tool_call(
                        int(cid), args=json.dumps(args, default=str, sort_keys=True)[:400])
                except Exception:  # noqa: BLE001
                    pass
    except Exception as err:
        print(f"[Atlas WARN] success-baseline log failed for {tool_name}: "
              f"{err!r}", file=sys.stderr)


_RESULT_META_KEYS = ("matched_rows", "returned_rows", "hit_count", "max_hits",
                     "scanned_rows", "row_count", "truncated", "scan_capped")


def _result_payload(result) -> dict:
    """The tool's own return dict, whether it arrived bare or wrapped in an
    MCP ToolResult (structured_content, or JSON text content)."""
    if isinstance(result, dict):
        return result
    sc = getattr(result, "structured_content", None)
    if isinstance(sc, dict):
        return sc
    for c in getattr(result, "content", None) or []:
        text = getattr(c, "text", None)
        if not text:
            continue
        try:
            obj = json.loads(text)
        except ValueError:
            continue
        if isinstance(obj, dict):
            return obj
    return {}


def _result_meta(result) -> dict:
    """The small structured facts about a result's completeness."""
    payload = _result_payload(result)
    out = {}
    for k in _RESULT_META_KEYS:
        v = payload.get(k)
        if isinstance(v, bool) or isinstance(v, int):
            out[k] = v
    return out


# ── Middleware ────────────────────────────────────────────────────────────────

class NarrationMiddleware(Middleware):
    """Single middleware over every @mcp.tool() invocation.

    Responsibilities (in order):
      1. Narration  — extract _note= arg, write as agent_message, strip arg.
      2. Case paths — resolve relative output/mount path args against the
         active case directory (refuse when no case is configured).
      3. Solution gate — deny args pointing into training answer keys.
      3b. Evidence-compat — refuse tools needing artifact classes absent
         from the case evidence profile (fail-open if no case/profile).
      4. DAIR gate  — block forensic tools when DAIR oversight has lapsed.
      5. Trace coverage — guarantee every call produces ≥1 trace entry:
           success    → baseline tool_call if the tool didn't self-log
           bad args   → tool_call(failure_class=analyst_error) + ToolError
                        envelope naming each invalid field
           exception  → tool_call(success=False, traceback) + re-raise ToolError
           cancel     → call_abandoned + re-raise CancelledError
           ToolError  → pass through (already structured, no extra entry)
    """

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next,
    ):
        args = dict(context.message.arguments or {})
        note = args.pop("_note", None)
        tool_name = context.message.name

        # 1. Narration
        if note and tool_name not in _SKIP_TOOLS:
            try:
                from core.execution_log import log
                log.record_agent_message(str(note),
                                         input_call_ids=_parent_cids())
            except Exception as e:
                _trace_narration_failure(e, str(note))

        # 2. Case-relative path resolution — before the gates so they (and
        # the tool body) see the real, resolved paths. A refusal is traced
        # as call_abandoned like the gates below (best-effort: the log may
        # legitimately be unconfigured on this path).
        try:
            resolved_args = _resolve_case_paths(tool_name, args)
        except ToolError as e:
            try:
                from core.execution_log import log
                log.record_call_abandoned(
                    tool_name,
                    f"case-path gate: {str(e)[:300]}",
                    input_call_ids=_parent_cids(),
                )
            except Exception:
                pass
            raise
        if resolved_args is not None:
            args = resolved_args

        # 2a'. Case-scope gate — a forensic tool reads the case's material,
        # not the machine it runs on. An absolute input path that exists
        # outside every place evidence can legitimately live is refused
        # before any tool sees it.
        hit = _find_outside_case_arg(tool_name, args)
        if hit:
            try:
                from core.execution_log import log
                log.record_call_abandoned(
                    tool_name, f"case-scope gate: {hit[:200]}",
                    input_call_ids=_parent_cids(),
                )
            except Exception:
                pass
            raise ToolError(
                f"Tool {tool_name} refused: {hit[:200]} is outside the case. "
                "Evidence lives under the case directory, an attached "
                "collection under /cases, /mnt or /media, or a root listed in "
                "ATLAS_EVIDENCE_ROOTS — read from there."
            )

        # 2a. Solution-material gate — BEFORE discovery-first so answer-key /
        # Solution paths get a specific deny reason even when the file is
        # missing (otherwise discovery_first would fire first on invent-paths).
        # 2b. Handling stop: material that must not be handled. A tool that
        # would carve, extract, copy, dump, render or submit it is refused
        # while the stop stands (core.handling_stop).
        try:
            from core.claim_graph import resolve_case_dir as _resolve_case_dir
            from core.handling_stop import gate as _handling_gate
            _hs_reason = _handling_gate(tool_name, args, _resolve_case_dir(None))
        except Exception:  # noqa: BLE001 - the gate never breaks a call on its own
            _hs_reason = None
        if _hs_reason:
            try:
                from core.execution_log import log
                log.record_call_abandoned(
                    tool_name, f"handling-stop gate: {_hs_reason[:200]}",
                    input_call_ids=_parent_cids(),
                )
            except Exception:
                pass
            raise ToolError(_hs_reason)

        # 2c. Threat-context TLP: a value an operator's source marked
        # TLP:RED or TLP:AMBER+STRICT is not sent to an outside service
        # (core.threat_context).
        try:
            from core.claim_graph import resolve_case_dir as _resolve_case_dir2
            from core.threat_context import tlp_refusal as _tlp_refusal
            _tlp_reason = _tlp_refusal(tool_name, args, _resolve_case_dir2(None))
        except Exception:  # noqa: BLE001 - the check never breaks a call on its own
            _tlp_reason = None
        if _tlp_reason:
            try:
                from core.execution_log import log
                log.record_call_abandoned(
                    tool_name, f"threat-context TLP: {_tlp_reason[:200]}",
                    input_call_ids=_parent_cids(),
                )
            except Exception:
                pass
            raise ToolError(_tlp_reason)

        if tool_name not in SOLUTION_GATE_ALLOWLIST:
            hit = _find_solution_arg(args)
            if hit:
                from core.paths import SOLUTION_BLOCK_MESSAGE
                try:
                    from core.execution_log import log
                    log.record_call_abandoned(
                        tool_name,
                        f"solution-material gate: blocked arg '{hit[:200]}'",
                        input_call_ids=_parent_cids(),
                    )
                except Exception:
                    pass
                raise ToolError(
                    f"Tool {tool_name} blocked: argument '{hit[:200]}' points "
                    f"into training solution material. {SOLUTION_BLOCK_MESSAGE}"
                )

        # 2b. Discovery-first input paths — after rewrite so we check the
        # real path. Missing invented paths become PROTOCOL refusals with a
        # discovery next step (or auto-rewrite when unique sibling/inventory
        # match exists). Never "succeed empty".
        discovery_rewrote = False
        try:
            rewritten = _refuse_missing_input_paths(tool_name, args)
            if isinstance(rewritten, dict):
                discovery_rewrote = rewritten != args
                args = rewritten
        except ToolError as e:
            try:
                from core.execution_log import log
                log.record_call_abandoned(
                    tool_name,
                    f"discovery-first/input-path gate: {str(e)[:300]}",
                    input_call_ids=_parent_cids(),
                )
            except Exception:
                pass
            raise

        # 2c. Context budget / input-scale — soft-refuse bulk dumps that cannot
        # fit the remaining LLM tool-output room (shard + affinity plan).
        try:
            from core import context_budget as _cb
            from core import input_scale as _iscale
            from core.deferred_intents import PROTOCOL_MARKER
            from core.execution_log import log as _elog
            _case = None
            try:
                _case = _elog.case_dir()
            except Exception:
                _case = None
            _budget = _cb.load_budget(_case) if _case else _cb.empty_budget()
            if _case and not _budget.get("available_for_tool_output_tokens"):
                try:
                    _budget = _cb.compute(_case, persist=True)
                except Exception:
                    pass
            # Repeat-call: same bulk fingerprint after a prior success/artifact.
            try:
                from core.deferred_intents import args_fingerprint
                fp = args_fingerprint(tool_name, args)
                prior = getattr(_elog, "_scale_success_fps", None) or {}
                hit = prior.get(fp) if isinstance(prior, dict) else None
                if hit and _iscale.is_bulk_parse_tool(tool_name):
                    arts = hit.get("artifact_paths") or []
                    msg = (
                        f"{PROTOCOL_MARKER} {tool_name} refused: identical "
                        f"input already ran (prior call_id="
                        f"{hit.get('call_id', '?')}). "
                        f"Query existing artifact(s) "
                        f"{arts[:5]!r} with table.* — do not re-run."
                    )
                    try:
                        _elog.record_call_abandoned(
                            tool_name,
                            f"repeat-call gate: {msg[:300]}",
                            input_call_ids=_parent_cids(),
                        )
                    except Exception:
                        pass
                    raise ToolError(msg)
            except ToolError:
                raise
            except Exception:
                pass
            refusal = _iscale.check(
                tool_name,
                args,
                case_dir=_case,
                available_tool_tokens=int(
                    _budget.get("available_for_tool_output_tokens") or 8000),
                max_dir_files=int(_budget.get("max_bulk_dir_files") or 1),
            )
            if refusal:
                import json as _json
                body = _json.dumps(refusal, indent=2, ensure_ascii=False)
                msg = f"{PROTOCOL_MARKER} {body}"
                try:
                    _elog.record_call_abandoned(
                        tool_name,
                        f"{refusal.get('gate', 'input_scale')}: "
                        f"{str(refusal.get('error') or '')[:300]}",
                        input_call_ids=_parent_cids(),
                    )
                except Exception:
                    pass
                raise ToolError(msg)
            # Disk-first: allow large single-file parses but force
            # agent-facing compaction after the tool returns.
            try:
                if _iscale.should_force_artifact_only(
                    tool_name,
                    args,
                    available_tool_tokens=int(
                        _budget.get("available_for_tool_output_tokens")
                        or 8000),
                ):
                    _elog._force_artifact_only = True
            except Exception:
                pass
        except ToolError:
            raise
        except Exception as _scale_err:
            print(f"[Atlas WARN] input-scale/context-budget check failed "
                  f"(fail-open): {_scale_err!r}", file=sys.stderr)

        # 2d. Wrong input kind (CSV→EvtxECmd, text→hive, …) — protocol INFO,
        # quarantine identical tool+path retries (investigate-latch storms).
        try:
            from core.deferred_intents import PROTOCOL_MARKER
            from core.input_kind import check_tool_input_kind
            _kind_case = None
            try:
                from core.execution_log import log as _elog
                _kind_case = _elog.case_dir()
            except Exception:
                _kind_case = None
            check_tool_input_kind(tool_name, args, case_dir=_kind_case)
        except ValueError as e:
            body = str(e)
            msg = body
            try:
                data = json.loads(body)
                if isinstance(data, dict) and data.get("gate") == "wrong_input_kind":
                    msg = json.dumps(data, indent=2, ensure_ascii=False)
            except json.JSONDecodeError:
                pass
            try:
                from core.execution_log import log
                log.record_call_abandoned(
                    tool_name,
                    f"wrong-input-kind gate: {msg[:300]}",
                    input_call_ids=_parent_cids(),
                )
            except Exception:
                pass
            raise ToolError(f"{PROTOCOL_MARKER} {msg}") from e
        except ToolError:
            raise
        except Exception as _kind_err:
            print(f"[Atlas WARN] input-kind check failed (fail-open): "
                  f"{_kind_err!r}", file=sys.stderr)

        # 2e. Disk-open policy — demote loop/FUSE open in Triage until
        # tsk.mmls/fls orientation (single authority; soft prompts failed).
        try:
            from core.execution_log import log as _elog
            _disk_case = _elog.case_dir()
        except Exception:
            _disk_case = None
        try:
            from core.runtime_capabilities import loop_fuse_demotion_refusal
            from core.deferred_intents import PROTOCOL_MARKER
            _disk_refusal = loop_fuse_demotion_refusal(
                tool_name, case_dir=_disk_case,
            )
            if _disk_refusal:
                _msg = json.dumps(_disk_refusal, indent=2, ensure_ascii=False)
                try:
                    from core.execution_log import log
                    log.record_call_abandoned(
                        tool_name,
                        f"disk-open policy: {_disk_refusal.get('error', '')[:300]}",
                        input_call_ids=_parent_cids(),
                    )
                except Exception:
                    pass
                raise ToolError(f"{PROTOCOL_MARKER} {_msg}")
        except ToolError:
            raise
        except Exception as _disk_err:
            print(f"[Atlas WARN] disk-open policy check failed "
                  f"(fail-open): {_disk_err!r}", file=sys.stderr)

        # 3. Evidence-assessment latch — no forensic / directing tools until
        # misc_inventory_evidence answers what exists, what is already
        # parsed, what still needs processing, and what to skip.
        try:
            from core.execution_log import log as _elog
            _case = _elog.case_dir()
        except Exception:
            _case = None
        if _case:
            try:
                from core.evidence_inventory_gate import (
                    INVENTORY_GATE_ALLOWLIST,
                    inventory_gate_refusal,
                    inventory_satisfied,
                )
                if (tool_name not in INVENTORY_GATE_ALLOWLIST
                        and not inventory_satisfied(_case)):
                    _msg = inventory_gate_refusal(tool_name)
                    try:
                        from core.execution_log import log
                        log.record_call_abandoned(
                            tool_name,
                            f"evidence-assessment gate: {_msg[:300]}",
                            input_call_ids=_parent_cids(),
                        )
                    except Exception:
                        pass
                    raise ToolError(_msg)
            except ToolError:
                raise
            except Exception as _inv_err:
                print(f"[Atlas WARN] evidence-assessment check failed "
                      f"(fail-open): {_inv_err!r}", file=sys.stderr)

        # 3b. Evidence-compat gate — refuse tools that need artifact classes
        # this case does not contain. Fail-open when no case/profile is
        # available (interactive probes, unit tests without a case tree).
        if _case:
            try:
                from core.evidence_profile import ensure_evidence_profile
                from tools.evidence_compat import check_tool_against_profile
                _profile = ensure_evidence_profile(_case)
                # The file the call names decides when it exists; the
                # profile decides when nothing is named (tools.evidence_compat).
                _refusal = check_tool_against_profile(
                    tool_name, _profile, args=args, case_dir=_case)
            except Exception as _ev_err:
                print(f"[Atlas WARN] evidence-compat check failed "
                      f"(fail-open): {_ev_err!r}", file=sys.stderr)
                _refusal = None
            if _refusal:
                try:
                    from core.execution_log import log
                    log.record_call_abandoned(
                        tool_name,
                        f"evidence-compat gate: {_refusal.get('error', '')[:300]}",
                        input_call_ids=_parent_cids(),
                    )
                except Exception:
                    pass
                raise ToolError(_refusal["error"])

        # 4. DAIR gate (+ deferred-intent backlog latch)
        if tool_name not in DAIR_GATE_ALLOWLIST:
            should_block, reason = _gate_decision()
            if should_block:
                from core.deferred_intents import PROTOCOL_MARKER
                intent_meta: dict = {}
                try:
                    from core.execution_log import log
                    intent_meta = log.record_deferred_intent(
                        tool_name,
                        args,
                        blocked_reason=reason,
                        input_call_ids=_parent_cids(),
                    ) or {}
                except Exception as err:
                    print(f"[Atlas WARN] deferred_intent record failed: "
                          f"{err!r}", file=sys.stderr)
                cid = intent_meta.get("call_id")
                open_n = intent_meta.get("open_count")
                action = intent_meta.get("action")
                cid_bit = f" deferred_intent=#{cid}" if cid else ""
                open_bit = (f" (open={open_n})"
                            if open_n is not None else "")
                action_bit = f" [{action}]" if action else ""
                raise ToolError(
                    f"{PROTOCOL_MARKER} Tool {tool_name} blocked: {reason}."
                    f"{cid_bit}{open_bit}{action_bit} "
                    f"Call dair_assess next — do NOT retry this forensic tool "
                    f"until dair_assess promotes it into priority_tools. "
                    f"This is a protocol info event, not a tool failure."
                )

        if ("_note" in (context.message.arguments or {})
                or resolved_args is not None
                or discovery_rewrote):
            new_message = context.message.model_copy(update={"arguments": args})
            context = context.copy(message=new_message)

        # 5. Trace coverage
        try:
            from core.execution_log import log as _log
            entries_before: int | None = len(_log._entries)
        except Exception:
            entries_before = None

        start = time.perf_counter()

        # Stamp the invoking MCP tool onto any tool_call the body self-logs
        # (subprocess executor) or the success-baseline writes, so the trace
        # records which typed tool produced each subprocess cmd. Same for the
        # evidence reference (image/mount path arg) — multi-host attribution.
        from core.execution_log import (current_action_id, current_evidence_ref,
                                        current_mcp_tool, next_action_id)
        _eref = _extract_evidence_ref(args)
        _tok = current_mcp_tool.set(tool_name)
        _eref_tok = current_evidence_ref.set(_eref or None)
        _aid_tok = current_action_id.set(next_action_id())

        try:
            result = await call_next(context)
            # A media-gated tool's printed bytes are checked after the call
            # (a live read, a decoder): an image or a video is withheld.
            try:
                from core.claim_graph import resolve_case_dir as _resolve_case_dir
                from core.handling_stop import post_gate as _handling_post
                _post_reason = _handling_post(tool_name, args, result, _resolve_case_dir(None))
            except Exception:  # noqa: BLE001
                _post_reason = None
            if _post_reason:
                raise ToolError(_post_reason)
        except ToolError:
            raise
        except asyncio.CancelledError:
            _trace_cancelled(tool_name, round(time.perf_counter() - start, 2))
            raise
        except (PydanticValidationError, FastMCPValidationError) as e:
            envelope = _validation_envelope(tool_name, e)
            _trace_validation_failure(tool_name, envelope,
                                      round(time.perf_counter() - start, 2))
            raise ToolError(envelope) from e
        except Exception as e:
            _trace_exception(tool_name, e, round(time.perf_counter() - start, 2))
            raise ToolError(f"{tool_name} raised {type(e).__name__}: {e}") from e
        finally:
            current_mcp_tool.reset(_tok)
            current_evidence_ref.reset(_eref_tok)
            current_action_id.reset(_aid_tok)

        # Resolve any matching deferred intent after a successful forensic run.
        try:
            from core.execution_log import log as _log
            _log.resolve_deferred_intent(tool_name, args)
        except Exception:
            pass

        # Runs after the contextvar reset — pass the ref explicitly.
        _trace_success_baseline(tool_name, round(time.perf_counter() - start, 2),
                                entries_before, result, evidence_ref=_eref,
                                args=args)

        # Proactive Brain wiki: once per forensic topic per run, append a
        # short cross-case lesson block when notes exist (token-capped).
        try:
            from core.brain.auto_consult import maybe_enrich_tool_result
            result = maybe_enrich_tool_result(tool_name, result, case_dir=_case)
        except Exception as _brain_err:
            print(f"[Atlas WARN] brain auto-consult failed (fail-open): "
                  f"{_brain_err!r}", file=sys.stderr)

        return result
