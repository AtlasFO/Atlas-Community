"""DAIR Director — Dynamic Approach to Incident Response phase tracking.

Runs as a parallel track alongside reason.*. Called after every tool batch to
assess which DAIR phase the investigation is in, whether to transition, and what
to focus on next. DAIR may surface candidate pivots, but candidate discovery is
advisory metadata and never mutates phase control flow by itself.

Active phases for Atlas (read-only forensic tool):
  Triage        — confirm initial IOCs, challenge for hallucinations, produce plan
  Collect       — gather raw artifacts per plan (ez.*, vol.*, tsk.*, strings.*)
  Analyze       — reason about collected artifacts; hypothesize on suspicious findings
  Scan          — sweep for lateral movement and pivot hosts (yara.*, net.*, enrich.*)
  Report        — terminal; emit Improve & Response recommendations

Detection is the assumed trigger (investigation already started). Improve &
Response actions are report recommendations only — never directed tool calls.
"""
from __future__ import annotations

import copy
import os
import re
import json
from dataclasses import dataclass
from typing import Optional

from fastmcp import FastMCP
from core.auth_ontology import (principal_appearance_cue_regex,
                                 principal_interactive_auth_cue_regex)
from core.envfile import env_int
from core.paths import DAIR_TIMEOUT
from tools.reasoning import _EMPTY_DIRECTIVES, _parse_directives, _cap_lines
from tools.tool_capabilities import (
    MANIFEST_VERSION,
    annotate_directives_with_manifest,
    format_tool_manifest_for_prompt,
)

mcp = FastMCP("dair")

# ── Backend configuration ─────────────────────────────────────────────────────

DAIR_BACKEND      = os.environ.get("DAIR_BACKEND") or ""
# The provider the role names, for the usage ledger's label: DAIR_BACKEND
# becomes the transport kind below once that provider is resolved.
DAIR_PROVIDER     = "" if DAIR_BACKEND in ("openai-compat", "claude") else DAIR_BACKEND
DAIR_URL          = (os.environ.get("DAIR_URL")
                     or os.environ.get("FOUNDATION_SEC_URL") or "")
DAIR_API_KEY      = (os.environ.get("DAIR_API_KEY")
                     or os.environ.get("HF_TOKEN") or "")
DAIR_MODEL        = os.environ.get("DAIR_MODEL") or ""

from core import llmhub as _llmhub
from core import providers as _providers

# Auth shape — see tools/reasoning.py.
DAIR_AUTH_HEADER = _providers.DEFAULT_AUTH_HEADER
DAIR_AUTH_PREFIX = _providers.DEFAULT_AUTH_PREFIX

# Set when the configured backend cannot be resolved. Never raises at import:
# tools/ is imported while the MCP server starts.
_BACKEND_CONFIG_ERROR = ""

# llmhub backend — only when the role explicitly selected it. An unset
# DAIR_BACKEND plus a hub API key must not silently become the hub.
if DAIR_BACKEND == "llmhub":
    DAIR_URL     = DAIR_URL or _llmhub.base_url()
    DAIR_API_KEY = DAIR_API_KEY or _llmhub.api_key()
    DAIR_MODEL   = DAIR_MODEL or _llmhub.model()
    DAIR_BACKEND = "openai-compat"
elif DAIR_BACKEND and DAIR_BACKEND not in ("openai-compat", "claude"):
    # A registered provider name (ATLAS_PROVIDERS) prefills the generic vars and
    # then continues down the openai-compat path, exactly like `llmhub`.
    try:
        _dair_provider = _providers.resolve(DAIR_BACKEND)
        DAIR_URL         = DAIR_URL or _dair_provider.base_url
        DAIR_API_KEY     = DAIR_API_KEY or _dair_provider.api_key
        DAIR_MODEL       = DAIR_MODEL or _dair_provider.model
        DAIR_AUTH_HEADER = _dair_provider.auth_header
        DAIR_AUTH_PREFIX = _dair_provider.auth_prefix
        DAIR_BACKEND     = "openai-compat"
    except _providers.UnknownProvider as _provider_error:
        _BACKEND_CONFIG_ERROR = f"DAIR_BACKEND is unusable: {_provider_error}"

_DEFAULT_COMPAT_MODEL = "fdtn-ai/Foundation-Sec-8B-Reasoning"
_CLAUDE_BACKEND_REMOVED = (
    "DAIR_BACKEND=claude is no longer supported. "
    "Use DAIR_BACKEND=llmhub or openai-compat. "
    "See docs/llm.md."
)

# The director's output is not capped: it rides the shared transport, which
# sends no completion ceiling and recovers a starved reply by bounding the
# thinking level instead. An assessment carries challenges, directives and
# recommended_actions, and a reasoning model spends thousands of tokens
# before its first visible one; below roughly 2000 visible tokens several
# models return an empty body with finish_reason=length rather than a short
# answer, because a reasoning channel is never read as the answer. The
# assessment then parses as empty and the phase machine falls back to its
# own valves. This is the director's role name for per-role model and
# thinking settings: its level (ATLAS_EFFORT_DAIR) is its own, not the
# reviewer's.
_DAIR_ROLE = "dair"

# ── Assess on change ──────────────────────────────────────────────────────────
# The DAIR window forces an assessment every few actions whether or not the
# investigation learned anything in between, and an assessment of the same
# recorded state is the same assessment. The cadence is kept (the window
# still closes and reopens on every call), but the director is only
# consulted when the recorded state differs from the one its standing
# assessment was made on. ATLAS_DAIR_REUSE_STANDING=0 consults it every time.
DAIR_REUSE_STANDING = env_int("ATLAS_DAIR_REUSE_STANDING", 1)
# A standing assessment stands for at most this many calls in a row before
# the director is consulted regardless: the signature is what the recorded
# state is made of today, and a dimension it does not carry must cost a
# duplicate assessment, never a run.
_REUSE_MAX_CONSECUTIVE = 3


def _active_backend() -> str:
    if DAIR_BACKEND:
        return DAIR_BACKEND
    if DAIR_URL:
        return "openai-compat"
    return ""


# ── Candidate pivot detection ────────────────────────────────────────────────
# DAIR records hosts/principals worth a follow-up look, but it does not mutate
# phase transitions. Earlier versions force-pushed and drained pivot queues from
# heuristic text extraction, and a generic token
# ("FINDINGS") could become a synthetic Triage target. Candidate pivots are
# therefore audit metadata only. The model/agent may choose to investigate them,
# but code never rewrites stack_action/next_phase from these regexes.
#
# Two detection paths run by default and are case-agnostic:
#   1. IPv4 — every host has one; the regex is rock-solid.
#   2. UNC paths — \\HOSTNAME\share is unambiguously a host reference,
#      regardless of the case's hostname naming convention.
# A third optional path handles case-specific hostname patterns that don't
# surface via UNC (e.g. bare "<prefix>-NN" mentions in narrative text): the
# operator sets ATLAS_PIVOT_HOSTNAME_PREFIXES="<prefix1>,<prefix2>,..." in
# .env and the prefix-based regex is compiled lazily inside
# _extract_host_tokens so env-var changes take effect without a server restart.

# IPv4 address anywhere in the summary text.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# UNC-path hostname extraction: captures the host portion of a \\HOST\share
# reference. Works for both IP and DNS-name forms; the IP form is filtered
# out downstream so it isn't double-counted.
_UNC_HOST_RE = re.compile(r"\\\\([A-Za-z0-9][\w.-]*)")


def _hostname_prefix_regex():
    """Compile the case-specific hostname regex from ATLAS_PIVOT_HOSTNAME_PREFIXES.

    Returns None if the env var is empty/unset (default case-agnostic mode —
    only IPv4 + UNC-path detection runs). Compiled lazily on each call so
    operators can adjust the env var between investigations without
    bouncing the MCP server, and so tests can monkeypatch it cleanly.
    """
    raw = os.environ.get("ATLAS_PIVOT_HOSTNAME_PREFIXES", "")
    prefixes = tuple(p.strip().lower() for p in raw.split(",") if p.strip())
    if not prefixes:
        return None
    return re.compile(
        rf"\b(?:{'|'.join(re.escape(p) for p in prefixes)})[-_]?\d+\b",
        re.IGNORECASE,
    )


# Tokens that look like hostnames but are forensic-jargon noise. Anything that
# matches the prefix-based regex but appears in this set is dropped before
# the new-host comparison. These words turn up in any Windows / DFIR case
# regardless of naming scheme:
#   - Forensic phase / tool jargon (scan, triage, system, registry, etc.)
#   - Common AV product names that frequently appear in event logs
#   - Networking and file-type tokens with digit suffixes that can match a
#     hostname-shaped regex (tcp4, http2, json5, etc.)
_PIVOT_STOP_WORDS = frozenset({
    "scan", "triage", "windows", "system", "report", "phase", "stage",
    "claude", "dair", "reason", "atlas", "mcp", "vol", "ez", "ntlm", "smb",
    "tcp", "udp", "dns", "http", "https", "rdp", "log", "evtx", "csv",
    "json", "xml", "mft", "pdf", "exe", "dll", "ps1", "bat", "vbs",
    "amcache", "shimcache", "prefetch", "registry",
    "mcafee", "windefend", "defender", "symantec", "crowdstrike", "sentinel",
})


# ── Work-order enforcement (deterministic safety net) ─────────────────────────
# The DAIR system prompt tells the model never to emit an empty priority_tools
# in a non-Report phase, but a weaker backend model sometimes does anyway. When
# it does, the agent gets no work order, improvises with raw shell, produces
# uncitable evidence, records nothing, and DAIR sees nothing to advance on — the
# exact infinite-Triage stall this guards against. These helpers
# guarantee, server-side, that an active phase always leaves with a real work
# order: (1) merge the most recent reason.* directives, (2) else fall back to an
# evidence-typed default, (3) force a Collect transition on the 3rd consecutive
# Triage/stay.

# Evidence-type → default Triage work order. Tool names use Atlas dotted MCP
# format (namespace.tool) to match what the DAIR model emits.
_DEFAULT_WORK_ORDERS: tuple[tuple[tuple[str, ...], list[str]], ...] = (
    (("pcap", ".pcap", ".pcapng", "capture"),
     ["net.tcpdump_read", "net.tcpdump_extract_http", "net.tcpdump_extract_dns",
      "net.http_session_inventory"]),
    ((".vbs", ".js", ".msc", ".hta", ".wsf", "vbscript", "jscript", "javascript",
      "powershell", "macro", "obfuscat", "encoded", "base64", "script"),
     ["misc.olevba_scan", "deob.decode_chain", "deob.base64_hunt",
      "strings.floss_extract"]),
    (("pe32", ".exe", ".dll", "portable executable", "pe file", "malware",
      "payload", "binary"),
     ["misc.pe_scanner", "strings.floss_extract", "hash.hash_file",
      "deob.base64_hunt"]),
    ((".eml", "email", "phish", "attachment", ".msg", ".emlx"),
     ["misc.parse_email", "misc.parse_msg_ole", "misc.parse_emlx",
      "strings.strings_extract", "hash.hash_file", "deob.base64_hunt"]),
    # VMDK / raw prefer TSK open — not loop/FUSE mounts as Triage default.
    ((".vmdk",),
     ["img.vmdk_chain_info", "img.vmdk_export_raw", "tsk.mmls", "tsk.fls"]),
    ((".e01", ".ex01"),
     ["ewf.mount_full_image", "tsk.mmls", "tsk.fls"]),
    ((".raw", ".dd", ".img", "disk image", "ntfs", "filesystem", "volume"),
     ["tsk.mmls", "tsk.fls"]),
    (("memory", ".mem", ".vmem", "dump", "ram"),
     ["vol.vol_info", "vol.vol_pslist", "vol.vol_netscan"]),
)

# Absolute last-resort work order when no evidence type is recognised: an
# inventory sweep (identify + hash everything) that yields typed cues for the
# next assessment. Deliberately NOT strings.strings_extract — re-prescribing
# a raw strings dump as the escape hatch recreates the success-but-empty
# loop it is meant to break.
_FALLBACK_WORK_ORDER = ["strings.file_identify_directory",
                        "hash.hash_directory"]

# On the Nth consecutive Triage/stay, force a transition to Collect.
_TRIAGE_MAX_PASSES = 3

# On the Nth consecutive Collect/stay that records no knowledge-state
# progress, force Analyze so Collect↔Analyze (or Collect forever) cannot burn
# the turn budget after evidence is already in hand. Aligns with the
# refuse-latch Analyze advance. A Collect pass that is still producing is
# never cut by this count alone.
_COLLECT_MAX_PASSES = 4

# After this many Triage→Collect round-trips WITH findings already recorded,
# the "smallest phase that can gather" is no longer Collect: force Analyze.
# The director's own prompt biases toward Collect, so without this valve an
# investigation ping-pongs Triage↔Collect forever and Analyze is never
# recommended.
_OSCILLATION_MAX_ROUNDTRIPS = 3
_OSCILLATION_MIN_FINDINGS = 3

# Phase cycle, used by the general evidence-exhaustion escape valve to compute
# the next phase to advance to.
_PHASE_ORDER = ["Triage", "Collect", "Analyze", "Scan", "Report"]

# After this many consecutive stays in a non-Triage/non-Report phase — while the
# prescribed tools keep failing on absent evidence — force a transition toward
# the next phase. Prevents the "prescribed net.* tools need a PCAP that doesn't
# exist" infinite loop: reason.synthesize is gated on current_phase==Report, so
# a run that can never advance is otherwise permanently stuck.
#
# Must be eligible no later than empty_loop / productive_stall (both fire after
# N-1=2 prior cycles with default N=3). A higher threshold here was the second
# half of the evidence_exhausted-shadowing bug: the general valves advanced
# the phase one cycle before this specific diagnosis could become eligible,
# so specificity arbitration never saw it as a candidate.
_STALL_MAX_STAYS = 3

# A phase whose identical work order keeps SUCCEEDING but yields zero new
# findings is stalled just as surely as one whose tools fail (a strings.*
# rabbit-hole, say). The valve above never fires there because nothing
# fails. After this many consecutive
# same-work-order/no-finding assessments, force a phase advance.
_EMPTY_LOOP_MAX_CYCLES = 3

# Substrings in a FAILED tool_call's output that signal its evidence is absent
# (the file it needed isn't there / is unreadable) rather than a transient error.
_MISSING_EVIDENCE_MARKERS = (
    "no such file", "bad magic number", "not found", "does not exist",
    "cannot open", "unable to open", "no pcap", "empty capture",
    "0 packets", "file is empty", "not a directory",
)

# Productive-stall valve: (3a)-(3c) above catch tool FAILURE and identical
# work-order re-issue, but not the general case: successful, VARIED tool
# calls that keep succeeding
# while the knowledge state (findings/evidence/hypotheses/readiness/timeline)
# stops changing. core.progress_signature is the single shared definition of
# "did we actually learn something", also intended for the wrap-up/blocker-
# extension and refuse-latch layers (see the DAIR-deadlock design notes).
# After this many consecutive same-phase/stay assessments with
# progress.changed==False, force a phase advance — regardless of whether the
# underlying tools succeeded.
_PROGRESS_STALL_MAX_CYCLES = int(
    os.environ.get("ATLAS_DAIR_STALL_MAX_CYCLES") or "3")

# The Analyze/Scan demotion of that valve to a soft hint (B0 / X5) is BOUNDED,
# not permanent. A soft hint sets note + transition_rationale only, so an
# Analyze/Scan run that ignores it has no DAIR-side escape left for a VARIED
# work order — empty_loop only catches an identical one — and falls through to
# core.run_budget, whose cheapest intervention is 25 no-progress turns and whose
# escape is 75. After this many consecutive barren cycles the hint has
# demonstrably not moved the phase, so the advance goes hard after all: one push
# this late cannot supply the repeating trigger the B0 / X5 Analyze<->Scan thrash
# needed, because the counter resets the moment the phase changes.
_PROGRESS_STALL_HARD_MAX_CYCLES = int(
    os.environ.get("ATLAS_DAIR_STALL_HARD_MAX_CYCLES")
    or str(3 * _PROGRESS_STALL_MAX_CYCLES))


def _case_root() -> str:
    """Best-effort case directory: derived from the execution log's trace path
    (walking up past analysis/exports/reports), falling back to cwd — both the
    CLI and MCP paths resolve the case from the working directory."""
    try:
        from core.execution_log import log as _elog
        p = getattr(_elog, "_path", None)
        if p:
            parent = os.path.dirname(os.path.abspath(p))
            if os.path.basename(parent) in ("analysis", "exports", "reports"):
                return os.path.dirname(parent)
            return parent
    except Exception:
        pass
    return os.getcwd()


def _evidence_blob() -> Optional[str]:
    """Space-joined, lowercased basenames of real evidence + staged media.

    Includes ``evidence/`` files and access-stage media from mount_plan
    (exported analysis raws, planned VMDKs) so DAIR work orders can ground
    on disk that Plane A registered outside ``evidence/``.

    Tri-state: returns None when the evidence dir can't be read (so callers do
    NOT treat evidence as "absent" on a read failure), else a possibly-empty
    string. An empty string means "evidence dir exists but holds no files" —
    meaningful absence that lets grounding reject evidence-typed work orders.
    """
    ev = os.path.join(_case_root(), "evidence")
    if not os.path.isdir(ev):
        return None
    names: list[str] = []
    try:
        for dirpath, _dirs, filenames in os.walk(ev):
            names.extend(filenames)
            if len(names) > 5000:  # bound the scan on huge evidence trees
                break
    except OSError:
        return None
    try:
        from core.evidence_access import staged_media_basenames
        names.extend(staged_media_basenames(_case_root()))
    except Exception:
        pass
    return " ".join(names).lower()


def _gaps_block() -> str:
    """What the director is otherwise not told: the high-value artifacts
    the case knows and never opened (with what each answers), and the
    parts of the requests still open with the kind of value each needs.
    The director prescribes from them or says why not."""
    lines: list[str] = []
    try:
        case = _case_root()
    except Exception:  # noqa: BLE001
        case = None
    if not case:
        return ""
    try:
        from core.artifact_value import unexamined_high_value
        unread = unexamined_high_value(case, limit=10)
    except Exception:  # noqa: BLE001
        unread = []
    if unread:
        lines.append("UNREAD HIGH-VALUE ARTIFACTS (known to the case, never opened):")
        for u in unread:
            path = str(u.get("path") or u.get("lpath") or u.get("name") or "")
            host = str(u.get("host") or "") if not u.get("path") else ""
            why = str(u.get("why") or "")
            lines.append(f"- {path}" + (f" [{host}]" if host else "") + (f": {why}" if why else ""))
    try:
        from core.investigation_tasks import actionable_tasks
        from core.request_parts import open_parts
        rows = []
        for t in actionable_tasks(case):
            pending = open_parts(t)
            if pending:
                rows.append(f"- {t.get('id')} {str(t.get('text') or '')[:70]}: "
                            + "; ".join(f"{p['id']} {p['text'][:40]} ({p['type']})" for p in pending[:6]))
    except Exception:  # noqa: BLE001
        rows = []
    if rows:
        lines.append("OPEN REQUEST PARTS (each needs a stated value of its kind, or a limitation):")
        lines += rows[:8]
    return "\n".join(lines)


def _gaps_digest() -> dict:
    """The two blocks as small values for the state signature: an artifact
    read or a part answered since the last assessment changes what the
    director is told, so the standing assessment must not stand."""
    try:
        case = _case_root()
    except Exception:  # noqa: BLE001
        case = None
    if not case:
        return {"unread": [], "open_parts": []}
    try:
        from core.artifact_value import unexamined_high_value
        unread = sorted(str(u.get("key") or u.get("path") or u.get("name") or "")
                        for u in unexamined_high_value(case, limit=10))
    except Exception:  # noqa: BLE001
        unread = []
    try:
        from core.investigation_tasks import actionable_tasks
        from core.request_parts import open_parts
        parts = sorted(f"{t.get('id')}:{p['id']}" for t in actionable_tasks(case) for p in open_parts(t))
    except Exception:  # noqa: BLE001
        parts = []
    return {"unread": [u for u in unread if u], "open_parts": parts}


def _mounted_volumes_block() -> str:
    """What the director cannot otherwise see: where the case's images are
    open right now and how a path on them is spelled. Without it the
    director prescribed paths under roots that exist nowhere and profiles
    named from the brief; the analyst overrode every one, at the cost of
    the director's own quality. Read from the mount plan's live view, so a
    mount that is gone is never advertised; the profile names are evidence
    and are bounded as such."""
    try:
        from core.mount_plan import mounted_volumes
        case = _case_root()
        volumes = mounted_volumes(case) if case else []
    except Exception:  # noqa: BLE001 - no plan, no block
        return ""
    if not volumes:
        return ""
    lines = ["MOUNTED VOLUMES (authoritative). A path the evidence names on an image is "
             "read at that image's mount point followed by the rest of the path, spelled "
             "as the volume spells it; tsk tools accept the mount point and the device "
             "alike. Prescribe paths under these roots only:"]
    # A handling stop stands over every volume: the director reads it first.
    try:
        from core.handling_stop import prompt_block as _stop_block
        _stop = _stop_block(case)
        if _stop:
            lines.append(_stop.strip())
    except Exception:  # noqa: BLE001 - the block stands without it
        pass
    for v in volumes[:12]:
        name = v.get("basename") or v.get("stem") or "image"
        kind = f" ({v['image_type']})" if v.get("image_type") else ""
        if v.get("rel"):
            line = f"- {name}{kind}: filesystem at {v['rel']}"
            if v.get("device_rel"):
                line += f"; device {v['device_rel']}"
            if v.get("profile_root"):
                shown = v.get("profiles") or []
                names = ", ".join(shown) or "(none)"
                total = int(v.get("profile_total") or 0)
                if total > len(shown):
                    names += f" ({len(shown)} of {total} shown)"
                line += f". Profile directory {v['rel']}/{v['profile_root']}: {names}"
            try:
                from core.baseline import status_line
                line += "; " + status_line(case, mount_point=v.get("mount_point") or "", stem=v.get("stem") or "")
            except Exception:  # noqa: BLE001 - the block stands without it
                pass
        else:
            line = (f"- {name}{kind}: device {v.get('device_rel') or v.get('device')}, "
                    "no filesystem mount (tsk tools read the device or the image)")
        lines.append(line)
    return "\n".join(lines)


def _default_work_order(*texts: str,
                        evidence_blob: Optional[str] = None) -> list[str]:
    """Pick a default work order from evidence-type cues in the given texts.

    When `evidence_blob` is provided (real filenames present under evidence/),
    a text cue only selects its order when the actual evidence backs it — this
    stops prescribing `net.*` tools for a brief that merely mentions "network"
    while no PCAP exists on disk. Passing None (evidence unreadable) preserves
    the legacy text-only behaviour.
    """
    blob = " ".join(t for t in texts if t).lower()
    grounded = evidence_blob is not None
    for cues, order in _DEFAULT_WORK_ORDERS:
        if not any(cue in blob for cue in cues):
            continue
        if grounded and not any(cue in evidence_blob for cue in cues):
            continue  # brief implies this type but evidence doesn't back it
        return list(order)
    # Nothing matched the text (or grounding rejected it): if evidence is
    # actually present, pick the order its files support even absent a text cue.
    if evidence_blob:
        for cues, order in _DEFAULT_WORK_ORDERS:
            if any(cue in evidence_blob for cue in cues):
                return list(order)
    return list(_FALLBACK_WORK_ORDER)


def _consecutive_phase_stays(phase: str) -> int:
    """Trailing run of `phase`/stay dair_call entries already in the trace."""
    count = 0
    try:
        from core.execution_log import log as _elog
        for e in reversed(_elog._entries):
            if e.get("type") != "dair_call":
                continue
            if e.get("current_phase") == phase and e.get("stack_action") == "stay":
                count += 1
            else:
                break
    except Exception as _e:
        import sys
        print(f"[Atlas WARN] dair phase-stay read failed: {_e!r}", file=sys.stderr)
    return count


def _consecutive_stalled_cycles(phase: str) -> int:
    """Trailing run of `phase`/stay dair_call entries already in the trace
    whose stored progress delta reported changed==False. Stops (does not
    count) at the first entry missing a `progress` field, so older traces
    recorded before this valve existed never trigger it retroactively."""
    count = 0
    try:
        from core.execution_log import log as _elog
        for e in reversed(_elog._entries):
            if e.get("type") != "dair_call":
                continue
            if e.get("current_phase") != phase or e.get("stack_action") != "stay":
                break
            progress = e.get("progress")
            if not isinstance(progress, dict) or "changed" not in progress:
                break
            if progress.get("changed") is False:
                count += 1
            else:
                break
    except Exception as _e:
        import sys
        print(f"[Atlas WARN] dair stall-count read failed: {_e!r}", file=sys.stderr)
    return count


def _collect_roundtrips() -> int:
    """Count Triage→Collect pushes recorded in the trace. The oscillation
    signature is this number
    growing while findings pile up and the investigation never advances."""
    n = 0
    try:
        from core.execution_log import log as _elog
        for e in _elog._entries:
            if (e.get("type") == "dair_call"
                    and e.get("current_phase") == "Triage"
                    and e.get("next_phase") == "Collect"):
                n += 1
    except Exception as _e:
        import sys
        print(f"[Atlas WARN] dair roundtrip read failed: {_e!r}", file=sys.stderr)
    return n


def _analyze_collect_roundtrips() -> int:
    """Count Analyze→Collect (or Collect←Analyze) push pairs in the trace.

    Without a damper, empty_loop advances Collect→Analyze while the model /
    playbook re-pushes Collect for “gaps”, burning budget on phase thrash.
    """
    n = 0
    try:
        from core.execution_log import log as _elog
        for e in _elog._entries:
            if e.get("type") != "dair_call":
                continue
            cur = e.get("current_phase")
            nxt = e.get("next_phase")
            sa = e.get("stack_action")
            if sa == "push" and cur == "Analyze" and nxt == "Collect":
                n += 1
            elif sa == "push" and cur == "Collect" and nxt == "Analyze":
                n += 1
    except Exception as _e:
        import sys
        print(f"[Atlas WARN] dair analyze/collect roundtrip read failed: "
              f"{_e!r}", file=sys.stderr)
    return n


def _report_collect_roundtrips() -> int:
    """Count Report↔Collect pushes."""
    n = 0
    try:
        from core.execution_log import log as _elog
        for e in _elog._entries:
            if e.get("type") != "dair_call":
                continue
            cur = e.get("current_phase")
            nxt = e.get("next_phase")
            sa = e.get("stack_action")
            if sa == "push" and cur == "Report" and nxt in ("Collect", "Analyze"):
                n += 1
            elif sa == "push" and cur in ("Collect", "Analyze") and nxt == "Report":
                n += 1
    except Exception as _e:
        import sys
        print(f"[Atlas WARN] dair report/collect roundtrip read failed: "
              f"{_e!r}", file=sys.stderr)
    return n


def _access_stage_settled_or_terminal() -> bool:
    """True when Access Stage no longer needs a Collect re-entry for disk open.

    Only meaningful for disk cases — tabular-only cases return False so a
    legitimate Report→Collect for new gatherable evidence is not blocked.
    """
    try:
        from core.evidence_access import disk_access_terminal, profile_has_disk
        case = _case_root()
        if not case or not profile_has_disk(case):
            return False
        return disk_access_terminal(case)
    except Exception:
        pass
    return False


def _sudo_auth_already_recorded() -> bool:
    """True when a tool result already carried failure_class=sudo_auth.

    Also recognizes privilege-preflight wording when an older classifier
    overwrote the class to tool_error.
    """
    try:
        from core.execution_log import log as _elog
        for e in _elog._entries:
            if e.get("type") != "tool_call":
                continue
            if str(e.get("failure_class") or "") == "sudo_auth":
                return True
            blob = " ".join(
                str(x) for x in (
                    e.get("stderr"), e.get("error"), e.get("cmd"),
                ) if x
            ).lower()
            if "sudo_auth" in blob:
                return True
            if ("sudo" in blob and (
                    "password is required" in blob
                    or "non-interactive sudo failed" in blob
                    or "sudo -n" in blob)):
                return True
    except Exception:
        pass
    return False


def _log_stack_phase() -> str:
    """Authoritative current phase from the execution-log stack (fail → '').

    The bootstrap ``session_start_default`` Triage seed is ignored so an
    agent-supplied ``phase_stack`` remains authoritative until a real
    ``dair_call`` advances the log stack (otherwise Scan/Analyze pivot
    observation is permanently shadowed by Triage).
    """
    try:
        from core.execution_log import log as _elog
        stack = getattr(_elog, "_phase_stack", None) or []
        if stack:
            if (
                len(stack) == 1
                and str(stack[0].get("entry_reason") or "")
                == "session_start_default"
            ):
                return ""
            return str(stack[-1].get("phase") or "")
        return str(getattr(_elog, "_current_phase", "") or "")
    except Exception:
        return ""


def _findings_count() -> int:
    try:
        from core.execution_log import log as _elog
        return sum(1 for e in _elog._entries if e.get("type") == "finding")
    except Exception:
        return 0


def _next_phase(phase: str) -> str:
    try:
        i = _PHASE_ORDER.index(phase)
    except ValueError:
        return "Report"
    return _PHASE_ORDER[min(i + 1, len(_PHASE_ORDER) - 1)]


def _tool_names(seq) -> frozenset:
    """Normalise a priority_tools list (strings or {'tool': ...} dicts) to a
    comparable set of tool names."""
    names = set()
    for t in seq or []:
        name = t if isinstance(t, str) else (t or {}).get("tool", "")
        if name:
            names.add(name)
    return frozenset(names)


def _empty_workorder_cycles(phase: str, proposed: frozenset) -> int:
    """Trailing count of same-phase/stay dair_call entries whose work order
    equals `proposed` with no finding recorded since the earliest of them.

    Walking the trace newest-first: a finding ends the (barren) run — every
    cycle counted so far happened after it; a different phase, stack action,
    or work order breaks the pattern outright."""
    if not proposed:
        return 0
    cycles = 0
    try:
        from core.execution_log import log as _elog
        for e in reversed(_elog._entries):
            etype = e.get("type")
            if etype == "finding":
                break
            if etype != "dair_call":
                continue
            if (e.get("current_phase") != phase
                    or e.get("stack_action") != "stay"):
                break
            prev = _tool_names(
                (e.get("directives") or {}).get("priority_tools"))
            if prev != proposed:
                break
            cycles += 1
    except Exception as _e:
        import sys
        print(f"[Atlas WARN] dair empty-loop read failed: {_e!r}",
              file=sys.stderr)
    return cycles


def _recent_missing_evidence_failures(window: int = 12) -> int:
    """Count recent FAILED tool_calls whose output signals absent evidence —
    the signature of prescribing tools whose required files don't exist."""
    hits = 0
    seen = 0
    try:
        from core.execution_log import log as _elog
        for e in reversed(_elog._entries):
            if e.get("type") != "tool_call":
                continue
            seen += 1
            if not e.get("success", True):
                blob = " ".join(str(e.get(k) or "") for k in
                                ("stdout_excerpt", "stderr", "error",
                                 "summary")).lower()
                if any(m in blob for m in _MISSING_EVIDENCE_MARKERS):
                    hits += 1
            if seen >= window:
                break
    except Exception as _e:
        import sys
        print(f"[Atlas WARN] dair missing-evidence read failed: {_e!r}",
              file=sys.stderr)
    return hits


def _recent_discovery_first_failures(window: int = 16) -> int:
    """Count recent abandoned/failed calls that are discovery_first protocol."""
    hits = 0
    seen = 0
    needles = (
        "discovery_first",
        "discovery-first",
        "authoritative discovery",
        "do not invent filenames",
        "input path(s) do not exist",
        "input-path gate",
    )
    try:
        from core.execution_log import log as _elog
        for e in reversed(_elog._entries):
            typ = e.get("type")
            if typ not in ("tool_call", "call_abandoned"):
                continue
            seen += 1
            blob = " ".join(
                str(e.get(k) or "") for k in
                ("stdout_excerpt", "stderr", "error", "summary", "reason")
            ).lower()
            if any(n in blob for n in needles):
                hits += 1
            if seen >= window:
                break
    except Exception as _e:
        import sys
        print(f"[Atlas WARN] dair discovery-first read failed: {_e!r}",
              file=sys.stderr)
    return hits


def _recent_reason_priority_tools() -> list[str]:
    """Merge priority_tools from the most recent reason.plan / reason.hypothesize
    trace entries (newest first, de-duplicated). Empty on any read failure."""
    merged: list[str] = []
    seen: set[str] = set()
    try:
        from core.execution_log import log as _elog
        for e in reversed(_elog._entries):
            if e.get("type") != "reason_call":
                continue
            for t in (e.get("directives") or {}).get("priority_tools", []) or []:
                name = t if isinstance(t, str) else (t or {}).get("tool", "")
                if name and name not in seen:
                    seen.add(name)
                    merged.append(name)
            if merged:  # stop at the newest reason call that carried tools
                break
    except Exception as _e:
        import sys
        print(f"[Atlas WARN] dair reason-merge read failed: {_e!r}",
              file=sys.stderr)
    return merged


def _consecutive_triage_stays() -> int:
    """Count the trailing run of Triage/stay dair_call entries already in the
    trace (i.e. before the current call is logged)."""
    count = 0
    try:
        from core.execution_log import log as _elog
        for e in reversed(_elog._entries):
            if e.get("type") != "dair_call":
                continue
            if e.get("current_phase") == "Triage" and e.get("stack_action") == "stay":
                count += 1
            else:
                break
    except Exception as _e:
        import sys
        print(f"[Atlas WARN] dair stay-count read failed: {_e!r}", file=sys.stderr)
    return count


# Nudge threshold: this many forensic tool calls with zero findings (or a
# findings/tool ratio below 1:5) means the agent is gathering intelligence
# without formalising it (belief starvation). Kept low so DAIR speaks
# before the agent-loop hard latch
# (agent.belief_starvation, default 3 substantive contacts) has to refuse
# further probes.
_FINDINGS_NUDGE_MIN_TOOLS = 4

_FINDINGS_NUDGE = (
    "Record findings for confirmed observations BEFORE the next batch — call "
    "misc.record_finding for each confirmed/likely fact from recent "
    "table.*/parser hits (account, host, path, time, action) with "
    "linked_call_id and input_call_ids. SUSPECTED/LIKELY is fine — do not "
    "defer formalisation waiting for reason.evaluate. Raw tool output that "
    "is never recorded cannot appear in the report.")

_TASK_DISPOSITION_NUDGE = (
    "CASE investigation tasks are still actionable and valid tabular contact "
    "already exists — before more disk-open work: (1) reason.evaluate_finding "
    "+ misc.record_finding for substantive table hits, (2) "
    "misc.update_investigation_task to answered/partial/"
    "blocked_missing_evidence. Coverage probes alone are not progress."
)

_EXPENSIVE_DISK_TOOLS = frozenset({
    "img.vmdk_export_raw", "img.losetup_create", "img.xmount_image",
    "ewf.mount_ntfs", "tsk.fls", "tsk.mactime", "plaso.create_timeline",
})


def _recent_tabular_contact() -> bool:
    """True when a successful table.* contact already ran this process."""
    try:
        from core.execution_log import log as _elog
        for e in reversed(list(_elog._entries or [])[-80:]):
            if e.get("type") != "tool_call" or not e.get("success"):
                continue
            blob = " ".join(
                str(e.get(k) or "") for k in ("cmd", "mcp_tool", "tool")
            ).casefold()
            if "table_" in blob or "table." in blob:
                return True
    except Exception:
        return False
    return False


def _task_disposition_lagging() -> bool:
    """Actionable CASE tasks + tabular contact + no beliefs yet."""
    try:
        from core.execution_log import log as _elog
        case = _elog.case_dir()
        if not case:
            return False
        from core.run_budget import belief_starvation_active
        if not belief_starvation_active(case):
            return False
        return _recent_tabular_contact()
    except Exception:
        return False


def _disk_units_unseen() -> bool:
    """True while the coverage ledger holds an intake container (a disk or
    memory image) nobody has opened."""
    try:
        from core.coverage_ledger import unseen_container_units
        from core.execution_log import log as _elog
        return bool(unseen_container_units(_elog.case_dir()))
    except Exception:  # noqa: BLE001 - no ledger or no case: nothing to protect
        return False


def _deprioritize_expensive_disk(priority_tools: list) -> list:
    """Keep disk tools available but after tabular/claim work when starving."""
    head: list = []
    tail: list = []
    for t in priority_tools or []:
        name = str(t)
        if name in _EXPENSIVE_DISK_TOOLS or name.replace("_", ".", 1) in (
                _EXPENSIVE_DISK_TOOLS):
            tail.append(t)
        else:
            head.append(t)
    # Ensure tabular/claim tools are visible when we demoted disk.
    for prefer in ("table.table_schema", "table.table_query",
                   "misc.record_finding", "misc.update_investigation_task"):
        if prefer not in head and prefer not in tail:
            head.append(prefer)
    ordered = head + tail
    # I3: when opened disk still has winevt on next_work_order, consume that
    # intent before deep carving (single access_workflow consumer).
    try:
        from core.access_workflow import prioritize_tools_for_access_workflow
        from core.execution_log import log as _elog
        case_dir = None
        try:
            case_dir = _elog.case_dir()
        except Exception:
            case_dir = None
        ordered = prioritize_tools_for_access_workflow(case_dir, ordered)
    except Exception:
        pass
    return ordered


def _findings_lagging() -> bool:
    """True when the trace shows substantial tool activity but few/no findings —
    the signal to nudge the agent to formalise what it has found."""
    try:
        from core.execution_log import log as _elog
        tool_calls = sum(1 for e in _elog._entries if e.get("type") == "tool_call")
        findings = sum(1 for e in _elog._entries if e.get("type") == "finding")
    except Exception as _e:
        import sys
        print(f"[Atlas WARN] dair findings-lag read failed: {_e!r}", file=sys.stderr)
        return False
    if tool_calls < _FINDINGS_NUDGE_MIN_TOOLS:
        return False
    return findings == 0 or findings * 5 < tool_calls


# TTP nudge: unmapped attack findings at this count trigger the mapping work
# order. Mirrors pre_report's blocking tolerance (TTP_UNMAPPED_BLOCK) so the
# analyst hears about mapping DURING Analyze, not first at the report gate,
# where mapping would be a last-minute checkbox.
_TTP_NUDGE_MIN_UNMAPPED = 2

_TTP_NUDGE = (
    "Map recorded findings to ATT&CK BEFORE the next batch: for each "
    "CONFIRMED/LIKELY finding without a technique, run correlate.mitre_map "
    "on its description, verify the top candidate with "
    "correlate.mitre_validate, and record the finding again with "
    "record_finding's mitre_techniques= and supersedes=<its call id>, which "
    "replaces it (without supersedes= it stands twice). Then sweep: any "
    "kill-chain tactic with "
    "evidence but no mapped technique gets one correlate.mitre_map pass. "
    "Run coverage.coverage_report to see the live mapping status.")


def _ttp_mapping_lagging(current_phase: str, next_phase: str) -> bool:
    """True when several attack-shaped CONFIRMED/LIKELY findings carry no
    technique while the run is in (or leaving for) its reasoning phases —
    the moment to fold mapping into the work order. Case-blind: computed
    from the run's own trace only."""
    if not (current_phase in {"Analyze", "Scan"} or next_phase == "Report"):
        return False
    try:
        from core.execution_log import log as _elog
        from tools.reasoning import (active_finding_entries,
                                     finding_carries_technique,
                                     is_attack_finding)
        unmapped = sum(
            1 for e in active_finding_entries(
                [e for e in _elog._entries if e.get("type") == "finding"],
                _elog.case_dir())
            if is_attack_finding(e) and not finding_carries_technique(e))
        return unmapped >= _TTP_NUDGE_MIN_UNMAPPED
    except Exception as _e:
        import sys
        print(f"[Atlas WARN] dair ttp-lag read failed: {_e!r}", file=sys.stderr)
        return False


# Valve specificity for advance arbitration. Lower wins when multiple valves
# apply on the same cycle. More *specific diagnoses* outrank general stall
# detectors so a later, broader valve cannot silently shadow an earlier,
# narrower one (the evidence_exhausted / productive_stall failure class).
_VALVE_SPECIFICITY = {
    "oscillation_cap": 10,       # Triage path diagnosis
    "analyze_collect_oscillation_cap": 12,  # Collect<->Analyze path diagnosis
    "triage_cap": 20,            # Triage duration cap
    "refuse_latch": 25,          # repeated wrong-phase refuses → force Analyze
    "evidence_exhausted": 30,    # known absent evidence
    "empty_loop": 40,            # identical barren work order
    # Collect duration cap. Deliberately NOT mirrored on triage_cap's 20: that
    # tier is arbitrary, because evidence_exhausted never fires in Triage and so
    # triage_cap competes with nothing specific. collect_cap does compete — both
    # it and evidence_exhausted fire on a stuck Collect — and a duration cap is
    # the more general detector of the two, so ranking it higher shadows the
    # causal diagnosis. Measured: at 22 it took the win and broke
    # test_forces_advance_after_repeated_missing_evidence.
    "collect_cap": 45,
    "productive_stall": 50,      # general knowledge-state stall (Collect/Triage)
    # Soft hints (Analyze/Scan) — lower wins when multiple soft notes apply
    "evidence_exhausted_hint": 30,
    "productive_stall_hint": 50,
}


def _set_soft_valve_hint(assessment: dict, hint: dict) -> None:
    """Keep the most specific soft hint; never overwrite with a broader one."""
    if not isinstance(hint, dict) or not hint.get("note"):
        return
    cur = assessment.get("soft_valve_hint")
    if not isinstance(cur, dict) or not cur.get("note"):
        assessment["soft_valve_hint"] = hint
        return
    if (
        _VALVE_SPECIFICITY.get(str(hint["note"]), 100)
        < _VALVE_SPECIFICITY.get(str(cur.get("note")), 100)
    ):
        assessment["soft_valve_hint"] = hint


@dataclass(frozen=True)
class _ValveCandidate:
    """One applicable advance valve. Collected, then arbitrated by specificity."""
    note: str
    next_phase: str
    rationale: str
    verification_satisfied: bool = False

    @property
    def specificity(self) -> int:
        return _VALVE_SPECIFICITY.get(self.note, 100)


def _select_valve(candidates: list[_ValveCandidate]) -> "_ValveCandidate | None":
    """Pick the most specific applicable valve. Stable tie-break on note name."""
    if not candidates:
        return None
    return min(candidates, key=lambda c: (c.specificity, c.note))


def _apply_valve(assessment: dict, winner: _ValveCandidate) -> str:
    """Mutate assessment transition fields from the arbitrated winner."""
    assessment["transition_recommended"] = True
    assessment["next_phase"] = winner.next_phase
    assessment["stack_action"] = "push"
    if winner.verification_satisfied:
        assessment["verification_satisfied"] = True
    if not assessment.get("transition_rationale"):
        assessment["transition_rationale"] = winner.rationale
    return winner.note


def _collect_advance_candidates(
    *,
    phase: str,
    assessment: dict,
    proposed: frozenset,
    delta,
) -> list[_ValveCandidate]:
    """Evaluate every advance valve independently. Composition happens in
    `_select_valve` — never via elif order. Report is not passed here."""
    candidates: list[_ValveCandidate] = []

    # Oscillation cap (Triage-only path diagnosis).
    if (phase == "Triage"
            and _collect_roundtrips() >= _OSCILLATION_MAX_ROUNDTRIPS
            and _findings_count() >= _OSCILLATION_MIN_FINDINGS
            and assessment.get("next_phase") in ("", "Collect")):
        candidates.append(_ValveCandidate(
            note="oscillation_cap",
            next_phase="Analyze",
            verification_satisfied=True,
            rationale=(
                f"Oscillation cap: {_collect_roundtrips()} Triage→Collect "
                f"round-trips with {_findings_count()} findings recorded — "
                "forcing Analyze so the evidence in hand gets correlated instead "
                "of re-collected."),
        ))

    # Triage max-pass cap.
    if (phase == "Triage"
            and assessment.get("stack_action") == "stay"
            and _consecutive_triage_stays() >= _TRIAGE_MAX_PASSES - 1):
        candidates.append(_ValveCandidate(
            note="triage_cap",
            next_phase="Collect",
            verification_satisfied=True,
            rationale=(
                f"Triage max-pass cap ({_TRIAGE_MAX_PASSES}) reached — forcing "
                "transition to Collect."),
        ))

    # Collect max-pass cap — stop Collect↔stay thrash once the gather phase
    # has had several cycles; Analyze is where correlation/synthesis live.
    # A pass that is still learning something (new findings, evidence,
    # hypotheses) is not thrash: the cap waits for the first barren pass, so
    # a large case is not pushed out of Collect while it is producing.
    if (phase == "Collect"
            and assessment.get("stack_action") == "stay"
            and _consecutive_phase_stays("Collect") >= _COLLECT_MAX_PASSES - 1
            and (delta is None or not delta.changed)):
        candidates.append(_ValveCandidate(
            note="collect_cap",
            next_phase="Analyze",
            verification_satisfied=True,
            rationale=(
                f"Collect max-pass cap ({_COLLECT_MAX_PASSES}) reached — forcing "
                "transition to Analyze so gathered evidence is correlated "
                "instead of re-collected."),
        ))

    # Collect↔Analyze oscillation damper — mirror Triage↔Collect cap.
    ac_trips = _analyze_collect_roundtrips()
    if (phase in ("Collect", "Analyze")
            and ac_trips >= _OSCILLATION_MAX_ROUNDTRIPS
            and _findings_count() >= _OSCILLATION_MIN_FINDINGS
            and assessment.get("next_phase") in ("", "Collect", "Analyze")
            and assessment.get("stack_action") in ("stay", "push", "")):
        # Hold Analyze (or advance to it) — refuse another Collect re-entry.
        if phase == "Analyze" and assessment.get("next_phase") == "Collect":
            assessment["next_phase"] = ""
            assessment["stack_action"] = "stay"
            assessment["transition_recommended"] = False
            assessment["transition_rationale"] = (
                f"Collect↔Analyze oscillation cap ({ac_trips} round-trips) — "
                "staying in Analyze; correlate findings instead of re-collecting."
            )
        elif phase == "Collect":
            candidates.append(_ValveCandidate(
                note="analyze_collect_oscillation_cap",
                next_phase="Analyze",
                verification_satisfied=True,
                rationale=(
                    f"Collect↔Analyze oscillation cap ({ac_trips} round-trips "
                    f"with {_findings_count()} findings) — forcing Analyze."),
            ))

    later = phase not in ("Triage", "Report") and assessment.get("stack_action") == "stay"

    # Refuse latch — repeated wrong-phase tool refuses (typically
    # reason.synthesize before Analyze) mean the agent is stuck asking for
    # synthesis work while DAIR stays in Triage/Collect. Force Analyze so
    # the refuse loop cannot burn the turn budget — synthesize is callable
    # from Analyze onward, so jumping straight to Report (the old escape)
    # is no longer needed and skipped the actual analysis phase.
    try:
        from core.investigation_exit import refuse_latch_tripped
        if (phase in ("Triage", "Collect")
                and refuse_latch_tripped(required_phase="Analyze")):
            candidates.append(_ValveCandidate(
                note="refuse_latch",
                next_phase="Analyze",
                verification_satisfied=True,
                rationale=(
                    "Refuse latch: reason.synthesize (or equivalent) was "
                    "refused repeatedly for being before Analyze while DAIR "
                    f"remained in {phase} — advancing to Analyze so the "
                    "refuse loop cannot repeat (synthesize is callable from "
                    "Analyze onward)."),
            ))
    except Exception as _rl_err:
        import sys as _sys
        print(f"[Atlas WARN] refuse-latch valve failed: {_rl_err!r}",
              file=_sys.stderr)

    # Evidence exhausted — invented-path storms must NOT advance and park
    # real evidence as "absent". Only hard-advance while gathering
    # (Collect→Analyze). Analyze→Scan force from missing-file storms caused
    # phase thrash while EVTX/HV evidence still existed (X11) — soft hint only.
    if (later
            and _consecutive_phase_stays(phase) >= _STALL_MAX_STAYS - 1
            and _recent_missing_evidence_failures() >= 2
            and _recent_discovery_first_failures() == 0):
        nxt = _next_phase(phase)
        rationale = (
            f"Evidence for the prescribed {phase} tools is absent "
            f"(repeated missing-file failures) — parking that work as out of "
            f"scope and advancing to {nxt} so the investigation can reach "
            f"Report.")
        if phase in ("Analyze", "Scan"):
            _set_soft_valve_hint(assessment, {
                "note": "evidence_exhausted_hint",
                "suggested_next_phase": nxt,
                "rationale": rationale,
            })
        else:
            candidates.append(_ValveCandidate(
                note="evidence_exhausted",
                next_phase=nxt,
                rationale=rationale,
            ))

    # Empty loop — identical barren work order with no new findings.
    # Keep as a hard escape (core valve set): true barren repetition.
    if (later
            and _empty_workorder_cycles(phase, proposed)
                >= _EMPTY_LOOP_MAX_CYCLES - 1):
        nxt = _next_phase(phase)
        candidates.append(_ValveCandidate(
            note="empty_loop",
            next_phase=nxt,
            rationale=(
                f"Empty-loop valve: the same {phase} work order has been "
                f"issued {_EMPTY_LOOP_MAX_CYCLES} consecutive times without "
                f"a single new finding — advancing to {nxt} instead of "
                f"repeating it."),
        ))

    # Productive stall — knowledge-state stall (progress_signature).
    # Hard advance only in Triage/Collect (get to Analyze). In Analyze/Scan
    # demote to a soft hint so general stall cannot force Analyze↔Scan /
    # Scan↔Report thrash (B0 / X5). empty_loop + refuse_latch remain hard.
    _in_triage_with_findings = False
    if phase == "Triage" and assessment.get("stack_action") == "stay":
        try:
            from core.execution_log import log as _elog
            _in_triage_with_findings = any(
                e.get("type") == "finding" for e in (_elog._entries or []))
        except Exception:
            _in_triage_with_findings = False
    _stalled = _consecutive_stalled_cycles(phase) if delta is not None else 0
    if ((later or _in_triage_with_findings)
            and delta is not None
            and not delta.changed
            and _stalled >= _PROGRESS_STALL_MAX_CYCLES - 1):
        nxt = "Collect" if phase == "Triage" else _next_phase(phase)
        reason_str = "; ".join(delta.reasons[:3]) or "no knowledge-state change"
        rationale = (
            f"Productive stall: {_PROGRESS_STALL_MAX_CYCLES} consecutive "
            f"{phase} assessments recorded no new findings, evidence "
            f"references, confirmed hypotheses, or readiness change "
            f"({reason_str}) — consider advancing to {nxt}."
        )
        if phase in ("Triage", "Collect") or _in_triage_with_findings:
            candidates.append(_ValveCandidate(
                note="productive_stall",
                next_phase=nxt,
                verification_satisfied=True,
                rationale=rationale.replace("consider advancing", "advancing"),
            ))
        elif _stalled >= _PROGRESS_STALL_HARD_MAX_CYCLES - 1:
            candidates.append(_ValveCandidate(
                note="productive_stall",
                next_phase=nxt,
                verification_satisfied=True,
                rationale=(
                    f"Productive stall (bounded escape): "
                    f"{_PROGRESS_STALL_HARD_MAX_CYCLES} consecutive {phase} "
                    f"assessments recorded no new findings, evidence "
                    f"references, confirmed hypotheses, or readiness change "
                    f"({reason_str}) — the soft hint did not move the "
                    f"phase, advancing to {nxt}."),
            ))
        else:
            _set_soft_valve_hint(assessment, {
                "note": "productive_stall_hint",
                "suggested_next_phase": nxt,
                "rationale": rationale,
            })

    return candidates


_TOOL_MENTION_RE = re.compile(
    r"\b(vol|ez|tsk|net|yara|table|misc|reason|coverage|hash|strings|af|deob"
    r"|ewf|live|enrich|hayabusa|correlate|claim|brain)\.([a-z][a-z_0-9]{2,})\b"
)


def _mcp_tool_name(dotted: str) -> str:
    """'ez.evtxecmd' → 'ez_ez_evtxecmd'; 'vol.vol_pslist' → 'vol_vol_pslist'."""
    if "." not in dotted:
        return dotted
    ns, rest = dotted.split(".", 1)
    rest = rest.strip()
    if rest.startswith(ns + "_"):
        return f"{ns}_{rest}"
    return f"{ns}_{ns}_{rest}"


def _executed_tool_blob() -> str:
    """Lowercased blob of every tool/cmd that actually ran in this trace."""
    parts: list[str] = []
    try:
        from core.execution_log import log as _elog
        for e in _elog._entries:
            t = e.get("type")
            if t in ("tool_call", "call_initiated", "reason_call",
                     "call_abandoned"):
                for k in ("cmd", "tool"):
                    v = e.get(k)
                    if v:
                        parts.append(str(v))
    except Exception:
        return ""
    return " ".join(parts).casefold()


def _known_manifest_tool_names() -> set[str]:
    """Dotted + leaf names from the capability manifest (planning vocabulary).

    Also registers short aliases for doubled MCP forms so ``table.schema``
    and ``table.table_schema`` are both recognised (Toolbox accepts both;
    fabricated-tool checks must not disagree).
    """
    names: set[str] = set()
    try:
        from tools.tool_capabilities import (
            _CAPABILITIES, _CLOSEOUT_TOOLS_ALWAYS,
        )
        tool_ids = []
        for cap in _CAPABILITIES:
            tool_ids.extend(cap.get("tools") or [])
        tool_ids.extend(_CLOSEOUT_TOOLS_ALWAYS)
        for t in tool_ids:
            dotted = str(t).casefold()
            names.add(dotted)
            if "." not in dotted:
                continue
            ns, rest = dotted.split(".", 1)
            names.add(rest)
            names.add(f"{ns}.{rest}")
            # table.table_schema → schema + table.schema
            if rest.startswith(ns + "_"):
                short = rest[len(ns) + 1:]
                if short:
                    names.add(short)
                    names.add(f"{ns}.{short}")
    except Exception:
        pass
    return names


def _summary_fabricated_tools(summary: str) -> set[str]:
    """Dotted tool names the summary invents that are not real tools.

    Mentions of known-manifest tools that have not run yet are PLANS, not
    fabrications — flagging them caused DAIR to dismiss
    misc.write_projected_final_report after it was merely deferred. Fabricated = unknown name (or claimed result without
    execution for names outside the manifest). Matching executed tools is
    still by leaf so aliases do not false-positive.
    """
    blob = _executed_tool_blob()
    known = _known_manifest_tool_names()
    fabricated: set[str] = set()
    for m in _TOOL_MENTION_RE.finditer(summary or ""):
        dotted = f"{m.group(1)}.{m.group(2)}"
        leaf = m.group(2).casefold()
        ns = m.group(1).casefold()
        stripped = leaf[len(ns) + 1:] if leaf.startswith(ns + "_") else leaf
        if dotted.casefold() in known or leaf in known or stripped in known:
            continue
        if stripped and stripped not in blob and leaf not in blob:
            fabricated.add(dotted)
    return fabricated


def _filter_inapplicable_tools(tools: list) -> tuple[list, list[str]]:
    """Drop prescribed tools whose evidence classes are absent from the case.

    The execution-side evidence-compat gate already refuses these calls; the
    fix here is to stop PRESCRIBING them (DAIR kept planning vol.* work on a
    case with no memory image because the keyword fallback matched 'dump').
    Fail-open: unknown tools and any gate error keep the tool.
    """
    kept: list = []
    dropped: list[str] = []
    tools = list(tools or [])
    try:
        case = _case_root()
        if not case:
            return list(tools), []
        from core.evidence_profile import ensure_evidence_profile
        from tools.evidence_compat import check_tool_against_profile
        profile = ensure_evidence_profile(case)
        # No usable profile (empty present_classes — e.g. no evidence tree
        # yet) → nothing trustworthy to filter against; keep everything.
        if not (profile or {}).get("present_classes"):
            return list(tools), []
        for t in tools or []:
            name = t if isinstance(t, str) else (t or {}).get("tool", "")
            refusal = None
            if name and "." in name:
                try:
                    refusal = check_tool_against_profile(
                        _mcp_tool_name(name), profile)
                except Exception:
                    refusal = None
            if refusal:
                dropped.append(name)
            else:
                kept.append(t)
    except Exception:
        return list(tools), []
    return kept, dropped


# Report-entry coverage gate: in-process deferral counter (fresh per run —
# DAIR lives in the agent process). After _REPORT_GATE_MAX_DEFERRALS the
# transition passes so the gate can never become a new deadlock; the loop's
# atlas_finish check and truthful finish classification still apply.
_REPORT_GATE_MAX_DEFERRALS = 3
_report_gate_deferrals = 0


def _report_entry_coverage_gate() -> tuple[str, list[str]]:
    """('note', redirect_tools) when Report entry must wait for coverage.

    Returns ("", []) when the transition may proceed: ledger ready for a
    degraded exit, no case dir, gate errored, or deferral budget exhausted.
    """
    global _report_gate_deferrals
    try:
        case = _case_root()
        if not case:
            return "", []
        from core.coverage_ledger import (
            open_unit_paths,
            ready_for_degraded_exit,
        )
        if ready_for_degraded_exit(case):
            return "", []
        gaps = open_unit_paths(case, limit=5)
        if not gaps:
            return "", []
        if _report_gate_deferrals >= _REPORT_GATE_MAX_DEFERRALS:
            return "", []
        _report_gate_deferrals += 1
        from core.coverage_ledger import open_units_read_hint, read_tools
        names = ", ".join(gaps)
        how = open_units_read_hint(case, limit=5)
        note = (
            f"report_entry_coverage: Report deferred "
            f"({_report_gate_deferrals}/{_REPORT_GATE_MAX_DEFERRALS}) — "
            f"unseen high-value evidence remains: {names}. Read these"
            + (f" ({how})" if how else "") + "; coverage.mark_blocked records "
            "a read that failed. Do this before entering Report."
        )
        return note, ["coverage.ledger_status", *read_tools(case, limit=5)]
    except Exception:
        return "", []


def _enforce_work_order(assessment: dict, raw_directives: dict,
                        summary: str, context: str) -> tuple[list[str], str]:
    """Guarantee a non-empty work order for active phases and enforce advance
    valves. Mutates `assessment` transition fields in place. Returns the final
    (priority_tools, enforcement_note) — note is "" when the model's own output
    already satisfied the contract.

    Report is exempt: it deliberately runs with an empty priority_tools.

    Advance valves are evaluated independently and arbitrated by specificity
    (`_select_valve`). Adding a new valve must declare a specificity tier in
    `_VALVE_SPECIFICITY`; it must not rely on elif ordering.
    """
    phase = assessment.get("current_phase", "Triage")

    # Progress signature: computed for every phase (including Report) so the
    # trace always carries this cycle's explainable knowledge-state delta for
    # telemetry, even on cycles where no valve below needs to act on it.
    # Stored on `assessment` under a leading-underscore key so dair_assess can
    # pull it out for record_dair_call and strip it before returning to the
    # LLM (the raw ID sets are irrelevant to the model).
    try:
        from core import progress_signature as _prog
        _prev_snap = _prog.load_prev_snapshot("cheap")
        _curr_snap = _prog.snapshot("cheap")
        _delta = _prog.diff(_prev_snap, _curr_snap)
        assessment["progress"] = _delta.to_dict()
        assessment["_progress_snapshot"] = _curr_snap.to_dict()
    except Exception as _prog_err:
        import sys as _sys
        print(f"[Atlas WARN] dair progress-signature failed: {_prog_err!r}",
              file=_sys.stderr)
        _delta = None

    if phase == "Report":
        # Report↔Collect damper lives here (Report skips advance valves).
        # Access Stage / sudo_auth blockers that Collect cannot clear must not
        # thrash phases.
        note = ""
        if assessment.get("stack_action") == "push" and (
                assessment.get("next_phase") in ("Collect", "Analyze")):
            settled = _access_stage_settled_or_terminal()
            sudo_seen = _sudo_auth_already_recorded()
            rc_trips = _report_collect_roundtrips()
            if settled or sudo_seen or (
                    rc_trips >= _OSCILLATION_MAX_ROUNDTRIPS
                    and _findings_count() >= _OSCILLATION_MIN_FINDINGS):
                assessment["next_phase"] = ""
                assessment["stack_action"] = "stay"
                assessment["transition_recommended"] = False
                assessment["transition_rationale"] = (
                    "Report↔Collect damper — stay in Report; document Access "
                    "Stage / Limitations via reason.synthesize UNRESOLVABLE "
                    "rather than re-entering Collect for the same disk-open "
                    "blocker."
                )
                note = "report_collect_damper"
        return list(raw_directives.get("priority_tools", []) or []), note

    tools = list(raw_directives.get("priority_tools", []) or [])
    note = ""
    evidence_blob = _evidence_blob()

    # What this assessment will actually prescribe: the model's own list, or —
    # when it is empty — whatever the fill logic at the bottom would supply.
    # The empty-loop valve must compare against the effective work order, or
    # the observed failure mode (model emits nothing, fallback re-prescribes
    # the same sweep every cycle) would never match.
    proposed = _tool_names(tools)
    if not proposed:
        proposed = (_tool_names(_recent_reason_priority_tools())
                    or _tool_names(_default_work_order(
                        context, summary, evidence_blob=evidence_blob)))

    winner = _select_valve(_collect_advance_candidates(
        phase=phase, assessment=assessment, proposed=proposed, delta=_delta,
    ))
    if winner is not None:
        note = _apply_valve(assessment, winner)
    else:
        # Soft valves (Analyze/Scan stall / false exhaustion) never force
        # stack transitions — surface as note + rationale only (B0).
        soft = assessment.get("soft_valve_hint")
        if isinstance(soft, dict) and soft.get("note"):
            note = str(soft["note"])
            if soft.get("rationale") and not assessment.get("transition_rationale"):
                assessment["transition_rationale"] = soft["rationale"]

    # Coverage gate on Report entry: the model must not advance the phase
    # stack into Report while the coverage ledger still has unseen high-value
    # units. Valve-forced transitions
    # (refuse latch etc.) are exempt — they exist to break refuse loops —
    # and after 3 deferrals the transition passes so this can never become
    # a new deadlock. Wall-clock close-out is handled by the loop, not here.
    if (winner is None
            and str(assessment.get("next_phase") or "") == "Report"
            and str(assessment.get("stack_action") or "") == "push"):
        deferral_note, redirect_tools = _report_entry_coverage_gate()
        if deferral_note:
            assessment["next_phase"] = ""
            assessment["stack_action"] = "stay"
            assessment["transition_recommended"] = False
            for t in reversed(redirect_tools):
                if t not in _tool_names(tools):
                    tools.insert(0, t)
            note = note or deferral_note

    # Never leave an active phase with an empty work order.
    if not tools:
        merged = _recent_reason_priority_tools()
        if merged:
            tools = merged
            note = note or "reason_merge"
        else:
            tools = _default_work_order(context, summary,
                                        evidence_blob=evidence_blob)
            note = note or "default_fallback"
        if not assessment.get("phase_rationale"):
            assessment["phase_rationale"] = (
                "Work order was empty; filled from "
                + ("recent reason.* directives" if note == "reason_merge"
                   else "evidence-typed default") + ".")

    # Discovery-first: invented-path storms → inject authoritative discovery
    # and strip speculative focus_paths so DAIR cannot re-prioritise guesses.
    # Require ≥2 recent discovery_first failures so a single refusal does not
    # latch injection on every subsequent dair_assess.
    try:
        if (_recent_discovery_first_failures() >= 2
                or _recent_missing_evidence_failures() >= 2):
            from core.discovery_first import (
                discovery_priority_tools,
                quarantine_guessed_paths,
            )
            disc = discovery_priority_tools()
            names = set(_tool_names(tools))
            for t in reversed(disc):
                if t not in names:
                    tools.insert(0, t)
                    names.add(t)
            note = note or "discovery_first_injection"
            dirs = raw_directives if isinstance(raw_directives, dict) else {}
            focus = dirs.get("focus_paths") or assessment.get("focus_paths")
            if focus:
                case = _case_root()
                cleaned = quarantine_guessed_paths(list(focus), case)
                dirs["focus_paths"] = cleaned
                assessment["focus_paths"] = cleaned
                if len(cleaned) < len(list(focus)):
                    assessment["focus_paths_sanitized"] = True
    except Exception as _df_err:
        import sys as _sys
        print(f"[Atlas WARN] dair discovery-first inject failed: "
              f"{_df_err!r}", file=_sys.stderr)

    return tools, note


# ── Output defaults ───────────────────────────────────────────────────────────

_EMPTY_ASSESSMENT: dict = {
    "current_phase": "Triage",
    "phase_rationale": "",
    "transition_recommended": False,
    "next_phase": "",
    "transition_rationale": "",
    "stack_action": "stay",
    "investigation_focus": "",
    "verification_satisfied": False,
    "verification_challenges": [],
    "recommended_actions": [],
}


# ── Parsing ───────────────────────────────────────────────────────────────────

def _parse_challenges(raw: str) -> list:
    """Extract VERIFICATION_CHALLENGES JSON array from model output."""
    if not raw:
        return []
    match = re.search(
        r"VERIFICATION_CHALLENGES:\s*(\[.*?\])\s*(?:DAIR_ASSESSMENT:|$)",
        raw,
        re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return []
    text = re.sub(r"\s*//[^\n]*", "", match.group(1))
    try:
        result = json.loads(text)
        return result if isinstance(result, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


# Keys the director's reply is read by. The prompt asks for a flat object with
# a `directives` sub-object, but reasoning models drift from the template in
# ways that all used to parse as the empty template: fields under a wrapper
# object, the label missing, prose with braces after the block. Each such
# reply cost a full model call and delivered the server fallbacks instead of
# the model's decision, so the reply is read by key at any depth.
_ASSESSMENT_KEYS = tuple(_EMPTY_ASSESSMENT) + ("deferred_intent_dispositions",)
_ASSESSMENT_SIGNATURE = frozenset(_ASSESSMENT_KEYS) | frozenset(_EMPTY_DIRECTIVES)


def _strict_object(properties: dict) -> dict:
    """A JSON-schema object as strict structured output requires it: every
    property required, none beyond the declared ones."""
    return {"type": "object", "properties": properties,
            "required": list(properties), "additionalProperties": False}


def _dair_response_schema() -> dict:
    """The director's reply as a JSON schema: the keys the parser fills in
    (_EMPTY_ASSESSMENT, _EMPTY_DIRECTIVES, the deferred-intent rulings), no
    others. Asked for as structured output so the reply is the object
    itself instead of prose the parser has to find it in; an endpoint that
    does not take the schema is learned and the parser reads free text as
    before."""
    string = {"type": "string"}
    strings = {"type": "array", "items": string}
    fields = {
        "current_phase": string,
        "phase_rationale": string,
        "transition_recommended": {"type": "boolean"},
        "next_phase": string,
        "transition_rationale": string,
        "stack_action": {"type": "string", "enum": ["stay", "push", "pop"]},
        "investigation_focus": string,
        "verification_satisfied": {"type": "boolean"},
        "verification_challenges": {"type": "array", "items": _strict_object({
            "claim": string,
            "challenge_method": string,
            "verified": {"type": ["boolean", "null"]},
            "confidence_impact": string,
            "notes": string,
        })},
        "recommended_actions": strings,
        "directives": _strict_object({
            "priority_tools": strings,
            "skip_tools": strings,
            "focus_pids": {"type": "array", "items": {"type": "integer"}},
            "focus_paths": strings,
            "max_depth": string,
            "next_hypothesis_triggers": strings,
            "curiosity_budget": {"type": "integer"},
            "required_actions": strings,
        }),
        "deferred_intent_dispositions": {"type": "array", "items": _strict_object({
            "call_id": {"type": "integer"},
            "action": {"type": "string", "enum": ["promote", "dismiss", "keep"]},
            "note": string,
        })},
    }
    assert set(fields) == set(_ASSESSMENT_KEYS) | {"directives"}
    assert set(fields["directives"]["properties"]) == set(_EMPTY_DIRECTIVES)
    return _strict_object(fields)


_DAIR_RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {"name": "dair_assessment", "strict": True,
                    "schema": _dair_response_schema()},
}

# Constraining the director's reply to the schema is off by default. Replaying
# recorded prompts against a live endpoint, the schema changed the ruling on
# every prompt whose unconstrained answer was stable across samples: a phase
# the model had read one way it then read another. A reply that is cheaper to
# parse is not worth a different decision, so this stays opt-in until a whole
# run shows the rulings hold. ATLAS_DAIR_RESPONSE_SCHEMA=1 enables it.
DAIR_RESPONSE_SCHEMA = env_int("ATLAS_DAIR_RESPONSE_SCHEMA", 0)


def _dair_response_format() -> dict | None:
    """The response_format for a director call, or None to leave the reply
    unconstrained."""
    return _DAIR_RESPONSE_FORMAT if DAIR_RESPONSE_SCHEMA else None


def _find_key(obj: dict, key: str) -> tuple[bool, object]:
    """Breadth-first lookup of `key` in nested dicts. Lists are not descended:
    their items are challenges, actions or stack frames, never the assessment."""
    queue = [obj]
    while queue:
        cur = queue.pop(0)
        if key in cur:
            return True, cur[key]
        queue.extend(v for v in cur.values() if isinstance(v, dict))
    return False, None


def _assessment_object(text: str) -> dict | None:
    """The first decodable JSON object carrying assessment keys, searched
    after the DAIR_ASSESSMENT label when present, else from the start.
    Balanced decoding, so text after the block cannot break it."""
    label = re.search(r"DAIR_ASSESSMENT", text, re.IGNORECASE)
    decoder = json.JSONDecoder()
    pos = text.find("{", label.end() if label else 0)
    while pos != -1:
        try:
            obj, _ = decoder.raw_decode(text, pos)
        except ValueError:
            obj = None
        if isinstance(obj, dict) and _ASSESSMENT_SIGNATURE & obj.keys():
            return obj
        pos = text.find("{", pos + 1)
    return None


def _parse_dair_assessment(raw: str) -> dict:
    """Extract the DAIR assessment from model output.

    Returns _EMPTY_ASSESSMENT on any parse failure so callers always have the
    expected keys. Missing keys in a successful parse are filled from the
    template; keys the model placed elsewhere are hoisted (see _ASSESSMENT_KEYS).
    """
    obj = None
    for text in (raw or "", re.sub(r"\s*//[^\n]*", "", raw or "")):
        obj = _assessment_object(text) if text else None
        if obj is not None:
            break
    if obj is None:
        return _EMPTY_ASSESSMENT.copy()
    parsed = {**_EMPTY_ASSESSMENT, **obj}
    for key in _ASSESSMENT_KEYS:
        if key not in obj:
            found, value = _find_key(obj, key)
            if found:
                parsed[key] = value
    if not isinstance(obj.get("directives"), dict):
        directives = {}
        for key in _EMPTY_DIRECTIVES:
            found, value = _find_key(obj, key)
            if found:
                directives[key] = value
        if directives:
            parsed["directives"] = directives
    return parsed


def _extract_host_tokens(text: str) -> set[str]:
    r"""Return the set of host references (IPs + hostnames) appearing in `text`.

    Detection sources:
      1. IPv4 addresses — always.
      2. UNC-path hostnames — `\\HOST\share` patterns; case-agnostic and
         unambiguous.
      3. Case-specific hostname prefixes — only if
         ATLAS_PIVOT_HOSTNAME_PREFIXES is set in the environment.

    Hostnames are normalized to uppercase so the set comparison against
    `case_context` is case-insensitive and matches how agents typically
    write them in narrative text (CORP-WS-01).

    A prose field a model answered with a list or a mapping is read as its
    text; an older trace may still hold one.
    """
    from core.execution_log import as_text
    text = as_text(text)
    if not text:
        return set()
    ips = set(_IPV4_RE.findall(text))
    hostnames: set[str] = set()

    # UNC-path host extraction. An IP in a UNC path is already counted via
    # _IPV4_RE — skip those so they aren't double-counted as a hostname.
    for h in _UNC_HOST_RE.findall(text):
        if _IPV4_RE.fullmatch(h):
            continue
        norm = h.upper().replace("_", "-")
        if norm.lower() in _PIVOT_STOP_WORDS:
            continue
        hostnames.add(norm)

    # Optional case-specific prefix-based detection. Lazy compile so changes
    # to ATLAS_PIVOT_HOSTNAME_PREFIXES take effect without a server restart.
    prefix_re = _hostname_prefix_regex()
    if prefix_re is not None:
        for h in prefix_re.findall(text):
            norm = h.upper().replace("_", "-")
            # Stop-word filter (e.g. SCAN3, WINDOWS-1).
            if norm.lower() in _PIVOT_STOP_WORDS:
                continue
            if norm.lower().split("-")[0] in _PIVOT_STOP_WORDS:
                continue
            hostnames.add(norm)

    return ips | hostnames


def _build_known_host_set(case_context: str) -> set[str]:
    """Union of all hosts referenced in case_context plus every
    investigation_focus from prior dair_call entries in the trace.

    The "known" set represents hosts the investigation has already touched.
    """
    known: set[str] = set()
    known |= _extract_host_tokens(case_context or "")
    try:
        from core.execution_log import log as _elog
        for e in _elog._entries:
            if e.get("type") != "dair_call":
                continue
            focus = e.get("investigation_focus") or ""
            known |= _extract_host_tokens(focus)
    except Exception as _read_err:
        # Fail-open: if we can't read the trace, treat known set as
        # case_context only. Worst case is a noisier push. Print so the
        # operator sees the cause when investigating pivot-detection bugs.
        import sys as _sys
        print(f"[Atlas WARN] dair host-context read failed: {_read_err!r}",
              file=_sys.stderr)
    return known


# ── Principal (account / identity) candidate detection ───────────────────────
# A new *host* is not the only thing worth surfacing for follow-up. A newly
# surfaced *principal* — an account or identity whose controller has never been
# established — is a candidate pivot too. These cues are recorded as
# candidate_pivots; they never force a focused sub-Triage by themselves.

# Built-in / generic tokens that are never a genuine new principal.
_PRINCIPAL_STOP_WORDS = frozenset({
    "administrator", "administrators", "admin", "admins", "guest",
    "defaultaccount", "system", "localsystem", "networkservice", "localservice",
    "homegroupuser", "homegroupuser$", "wdagutilityaccount", "trustedinstaller",
    "account", "accounts", "user", "users", "username", "principal",
    "creation", "created", "creates", "create", "new", "local", "named",
    "called", "the", "this", "that", "was", "were", "is", "are", "an", "a",
    "credential", "credentials", "name", "identity", "logon", "login",
    # Pronouns / fillers that can sit immediately before an auth verb
    # ("who logged in", "successfully authenticated") — never a principal name.
    "who", "they", "he", "she", "someone", "and", "then", "also", "has",
    "have", "had", "successfully", "remotely", "interactively", "session",
    # Verbs / connectives that can follow a cue word once the auth-cue path
    # reaches name extraction ("user logged in" must not yield 'logged').
    "logged", "logging", "authenticated", "signed", "accessed", "connected",
    "ran", "opened", "performed", "enabled", "disabled", "established",
    "via", "from", "with", "network", "remote", "interactive",
    "in", "on", "to", "at", "by", "of", "as", "out", "up",
    # Windows filesystem / registry vocabulary that pattern-matches the
    # name-after-cue shapes but is never a principal ("profile path ...
    # PROFILES", "Users\Public\Music staging dir").
    "profiles", "profilelist", "windows", "system32", "syswow64",
    "programdata", "appdata", "ntuser", "usrclass", "prefetch", "winevt",
    "config", "temp", "public", "default", "desktop", "documents",
    "downloads", "music", "pictures", "videos",
})

# Does the text describe an account being *created* (vs merely mentioned)?
_ACCOUNT_CREATION_CUE_RE = re.compile(
    r"(?:\baccount\s+creat\w*|\bcreat\w+\b.{0,30}?\baccount\b"
    r"|\bnew\s+(?:local\s+)?(?:admin\w*|user)\s+account\b"
    r"|\bcovert\s+(?:local\s+)?(?:admin\w*|account)\b"
    r"|\bbackdoor\s+account\b|\brogue\s+account\b"
    r"|\bplanted\b.{0,20}?\baccount\b|\b4720\b)",
    re.IGNORECASE,
)

# Tier A (forced push): a previously-unseen identity that AUTHENTICATES
# INTERACTIVELY or over RDP — the highest-signal "second operator" cue. An
# unknown identity doing an interactive / RemoteInteractive logon is almost
# always a distinct human principal, so it earns the same forced Triage push
# as a freshly-created account. (Creation-only detection missed exactly this:
# a second principal who arrives by RDP rather than by creating an account.)
_PRINCIPAL_INTERACTIVE_AUTH_CUE_RE = principal_interactive_auth_cue_regex()

# Tier B: noisier first-appearances — network/service logon, a first-seen
# correspondent. Recorded with cue="appearance" for audit/debugging.
_PRINCIPAL_APPEARANCE_CUE_RE = principal_appearance_cue_regex()

# Capture a principal's *name* from creation/identity/authentication context.
# Group 1 = name after a cue word (account/user/principal/named/called);
# group 2 = a quoted/backticked name immediately preceding "account"/"admin";
# group 3 = a name immediately preceding an auth verb ("svc_x logged in",
# "maint_op authenticated") — needed because an interactive-logon summary often
# leads with the name and has no adjacent cue word.
# Names must END on a word character: `[\w.$-]` mid-token keeps
# DOMAIN.LOCAL\user shapes, but a sentence-ending "principal PROFILES." must
# not swallow the period: a junk token such as 'PROFILES.' would become an
# undispositionable identity that deadlocks pre_report_check.
# A capture is kept only when it is written as a name (quoted, qualified, a
# capital, a digit or punctuation: core.ioc_catalog.written_as_principal).
# The word after a cue is otherwise the next English word: "principal
# identified" and "user profile" are not accounts the report gate should
# demand a controller for.
_ACCOUNT_NAME_RE = re.compile(
    r"(?:\b(?:account|user|username|principal|named|called|subject|suspect)\s*:?\s+[\"'`]?"
    r"([A-Za-z](?:[\w.$-]{0,39}[\w$])?)[\"'`]?)"
    r"|(?:[\"'`]([A-Za-z](?:[\w.$-]{0,39}[\w$])?)[\"'`]\s+(?:account|admin))"
    r"|(?:\b([A-Za-z](?:[\w.$-]{0,39}[\w$])?)\s+(?:logged ?in|authenticated|signed ?in))",
    re.IGNORECASE,
)


def _extract_principal_tokens(text: str, require_cue: bool = True,
                              cue: str = "creation") -> set[str]:
    """Return new-principal tokens (uppercased account names, ``RID<n>``,
    SIDs) appearing in ``text``.

    ``require_cue=True`` (summary side): only emit tokens when the text also
    carries a *cue* that this is a genuine new principal, not an ordinary
    mention. ``cue`` selects which cue families gate (precision ↓ as breadth ↑):

      - ``"creation"`` (default, back-compat): account-*creation* only
        (4720 / "account created" / "new admin account" / covert/backdoor).
      - ``"forced"``: creation OR interactive/RDP authentication (logon type
        2/10, 4778/4779, "logged in") — the Tier-A "second operator" cues that
        warrant a forced Triage push.
      - ``"appearance"``: Tier-B first-appearance only (network logon type 3,
        generic 4624/4625, first-seen correspondent).
      - ``"any"``: union of all three.

    The default stays ``"creation"`` so the conservative behaviour is unchanged
    for every existing caller; candidate collection opts into ``"forced"`` /
    ``"appearance"`` explicitly. ``require_cue=False`` (known side): extract any
    named principal from case_context / prior investigation_focus / pivot focus
    lines so it is excluded from the new set (and so report-time harvesting can
    read surfaced principals back).
    """
    from core.execution_log import as_text
    text = as_text(text)
    if not text:
        return set()
    if require_cue:
        creation = _ACCOUNT_CREATION_CUE_RE.search(text)
        interactive = _PRINCIPAL_INTERACTIVE_AUTH_CUE_RE.search(text)
        appearance = _PRINCIPAL_APPEARANCE_CUE_RE.search(text)
        if cue == "creation":
            hit = creation
        elif cue == "forced":
            hit = creation or interactive
        elif cue == "appearance":
            hit = appearance
        else:  # "any"
            hit = creation or interactive or appearance
        if not hit:
            return set()
    from core.ioc_catalog import written_as_principal
    out: set[str] = set()
    for m in _ACCOUNT_NAME_RE.finditer(text):
        name = m.group(1) or m.group(2) or m.group(3)
        if (name and name.lower() not in _PRINCIPAL_STOP_WORDS
                and written_as_principal(name, text)):
            out.add(name.upper())
    for rid in re.findall(r"\bRID\s*(\d{3,})\b", text, re.IGNORECASE):
        out.add(f"RID{rid}")
    for sid in re.findall(r"\bS-1-5-[\d-]+\b", text):
        out.add(sid.upper())
    return out


def _build_known_principal_set(case_context: str) -> set[str]:
    """Principals already named in case_context or any prior dair_call
    investigation_focus — the set a new principal is measured against. Uses
    cue-free extraction so a principal already under investigation (its
    controller question recorded in a focus line) counts as known."""
    known: set[str] = set()
    known |= _extract_principal_tokens(case_context or "", require_cue=False)
    try:
        from core.execution_log import log as _elog
        for e in _elog._entries:
            if e.get("type") != "dair_call":
                continue
            focus = e.get("investigation_focus") or ""
            known |= _extract_principal_tokens(focus, require_cue=False)
    except Exception as _read_err:
        import sys as _sys
        print(f"[Atlas WARN] dair principal-context read failed: {_read_err!r}",
              file=_sys.stderr)
    return known


# Candidate-detection allow-list. Hosts/principals surfaced from these phases
# are eligible for candidate_pivots; Triage is excluded because Triage is
# *about* the host/principal already under investigation.
_PIVOT_ELIGIBLE_PHASES = frozenset({"Scan", "Analyze", "Collect"})


def _strip_blocks(text: str) -> str:
    """Remove VERIFICATION_CHALLENGES and DAIR_ASSESSMENT blocks from text."""
    text = re.sub(
        r"\*{0,2}VERIFICATION_CHALLENGES\*{0,2}\s*:?\*{0,2}.*",
        "", text, flags=re.DOTALL | re.IGNORECASE,
    )
    text = re.sub(
        r"\*{0,2}DAIR_ASSESSMENT\*{0,2}\s*:?\*{0,2}.*",
        "", text, flags=re.DOTALL | re.IGNORECASE,
    )
    return text.rstrip()


# ── Backend implementations ───────────────────────────────────────────────────

def _ask_openai_compat(system: str, user: str) -> dict:
    """The director's request over the one transport (see tools/reasoning.py)."""
    from agent.llm import LLMHubClient
    _empty = {"success": False, "raw": "", "input_tokens": 0, "output_tokens": 0}

    if not DAIR_URL:
        return {**_empty, "error": "DAIR_URL not set for openai-compat backend"}

    model = DAIR_MODEL or _DEFAULT_COMPAT_MODEL
    try:
        from core.execution_log import log as _elog
        _elog.record_call_initiated("dair_assess", "openai-compat", {"model": model, "url": DAIR_URL})
    except Exception as _e:
        import sys; print(f"[Atlas WARN] record_call_initiated failed: {_e}", file=sys.stderr)
    try:
        client = LLMHubClient(
            base_url=DAIR_URL, api_key=DAIR_API_KEY, model=model,
            timeout=DAIR_TIMEOUT,
            # The resolved provider's name: DAIR_BACKEND became the
            # transport kind, and under it the role learned its request
            # shape apart from the analyst's.
            provider=DAIR_PROVIDER if _providers.is_declared(DAIR_PROVIDER) else "",
            auth_header=DAIR_AUTH_HEADER, auth_prefix=DAIR_AUTH_PREFIX,
            usage_provider=DAIR_PROVIDER)
        from tools.reasoning import _compact_user_message
        _messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        # The reply is asked for as the assessment object itself; an endpoint
        # that rejects the schema is learned and the text parser below reads
        # the reply either way.
        resp = client.chat(
            _messages, role=_DAIR_ROLE, temperature=None,
            response_format=_dair_response_format(),
            compact=lambda msgs: [msgs[0], {"role": "user",
                                            "content": _compact_user_message(user)}])
        raw = resp.content.strip()
        if not raw:
            # What the model was writing when nothing answered: the reply
            # of a cut or empty call is kept nowhere else, and the shape of
            # a runaway (a loop, a list, an essay) is what a guard needs.
            thinking = resp.reasoning or ""
            return {
                **_empty,
                "error": resp.starved_reason(),
                "input_tokens": resp.input_tokens,
                "output_tokens": resp.output_tokens,
                "reasoning_tokens": resp.reasoning_tokens,
                "finish_reason": resp.finish_reason,
                "gate": "empty_reason_response",
                "reply_cut": {"reasoning_chars": len(thinking),
                              "reasoning_head": thinking[:600],
                              "reasoning_tail": thinking[-600:]},
            }
        return {
            "success": True,
            "raw": raw,
            "input_tokens": resp.input_tokens,
            "output_tokens": resp.output_tokens,
            "reasoning_tokens": resp.reasoning_tokens,
            "finish_reason": resp.finish_reason,
        }
    except Exception as e:
        try:
            from core.execution_log import log as _elog
            _elog.record_call_abandoned("dair_assess", str(e))
        except Exception as _log_err:
            # Best-effort — we're already in the failure path; surface to
            # stderr so the operator sees the double-fault. Not routed
            # through record_system_error because that path can fail for
            # the same reason and we'd risk infinite recursion.
            import sys as _sys
            print(f"[Atlas WARN] dair record_call_abandoned failed during "
                  f"backend error: {_log_err!r}", file=_sys.stderr)
        return {**_empty, "error": str(e)}


def _ask(system: str, user: str) -> dict:
    backend = _active_backend()

    def _config_error(message: str) -> dict:
        return {
            "success": False,
            "raw": "",
            "input_tokens": 0,
            "output_tokens": 0,
            "error": message,
        }

    if not backend:
        return _config_error(
            "DAIR_BACKEND is not configured. Set it to a provider name "
            "(llmhub, or a name from ATLAS_PROVIDERS) or openai-compat with "
            "DAIR_URL. Telekom LLM Hub is not used unless you select it.")
    if backend == "claude":
        return _config_error(_CLAUDE_BACKEND_REMOVED)
    if _BACKEND_CONFIG_ERROR:
        return _config_error(_BACKEND_CONFIG_ERROR)
    # Positive list — see tools/reasoning.py._ask for why the old silent
    # fall-through is no longer acceptable with several providers registered.
    if backend != "openai-compat":
        return _config_error(
            f"DAIR_BACKEND={backend!r} is not a known backend. Use "
            f"openai-compat, or one of these registered providers: "
            f"{', '.join(_providers.names())}.")
    return _ask_openai_compat(system, user)


def _log_dair(assessment: dict, input_tokens: int, output_tokens: int,
              inputs: dict | None = None,
              input_call_ids: list[int] | None = None,
              candidate_pivots: list[dict] | None = None) -> int:
    try:
        from core.execution_log import log
        return log.record_dair_call(
            current_phase=assessment.get("current_phase", ""),
            phase_rationale=assessment.get("phase_rationale", ""),
            transition_recommended=assessment.get("transition_recommended", False),
            next_phase=assessment.get("next_phase", ""),
            transition_rationale=assessment.get("transition_rationale", ""),
            stack_action=assessment.get("stack_action", "stay"),
            investigation_focus=assessment.get("investigation_focus", ""),
            verification_satisfied=assessment.get("verification_satisfied", False),
            verification_challenges=assessment.get("verification_challenges", []),
            recommended_actions=assessment.get("recommended_actions", []),
            directives=assessment.get("directives", {}),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            inputs=inputs,
            input_call_ids=input_call_ids,
            pending_pivots=assessment.get("pending_pivots") or None,
            candidate_pivots=candidate_pivots,
            progress=assessment.get("progress") or None,
            progress_snapshot=assessment.get("_progress_snapshot") or None,
            work_order_enforced=assessment.get("work_order_enforced") or "",
        )
    except Exception as e:
        import sys
        print(f"[Atlas WARN] _log_dair failed: {e}", file=sys.stderr)
        return 0


# ── System prompt ─────────────────────────────────────────────────────────────

_DAIR_SYS = """\
You are the DAIR Director for a read-only digital forensic investigation. \
Your role is to plan each investigation batch and track phase progression.

YOUR ROLE AS INVESTIGATION PLANNER:
You do not merely assess what was found — you prescribe exactly what to investigate \
next. The investigator executes ONLY what you list in directives.priority_tools. \
Nothing outside that list will be run.
- Non-Report phases: priority_tools MUST always be non-empty. If you have nothing \
  new to prescribe for the current phase, transition to the next phase instead of \
  emitting stay with an empty list. An empty priority_tools with stack_action "stay" \
  is invalid and stalls the investigation.
- investigation_focus: one sentence stating the question this batch answers.
- Report phase only: priority_tools is empty; populate recommended_actions instead. \
When a REPORT GATE block is present and reads READY_TO_REPORT: false, the first \
recommended actions MUST address each blocking issue concretely — which finding to \
re-cite from which call, which finding to lower, which blocker to state as \
UNRESOLVABLE in reason.synthesize — whatever the tool results summary says about \
them; the gate's verdict outranks the investigator's account of it. \
Each recommended action names its scope (host | network | estate) and the finding \
it derives from. Scope must match what the findings establish: when they show an \
impact TTP (T1486/T1490), multi-host exposure, or high-privilege attacker activity \
(log clearing, PsExec, DC access), host-local IOC sweeps are NOT enough — include \
estate-level actions: containment/isolation decision, domain-wide credential \
hygiene (krbtgt reset consideration when a DC is in reach), backup integrity \
verification before restore, data-leak impact assessment when double-extortion is \
claimed, and IR/management escalation.
- priority_tools is the complete work order — not a priority ranking. List every \
  tool needed to answer investigation_focus. The investigator runs them all.

CURIOSITY BUDGET (directives.curiosity_budget):
priority_tools is a convergent work order; on its own it drives single-actor \
lock-in and shallow coverage. The curiosity_budget is its counterweight — the \
number of read-only probes the investigator may run of their OWN choosing this \
batch, on top of priority_tools, to chase a hunch about a LESS-OBVIOUS artifact. \
Set it per batch:
  - Triage / Analyze: 2-3 (these phases surface the leads worth chasing).
  - Collect / Scan: 1-2.
  - Report: 0 (the investigation is converging; no new exploration).
Raise it (to 3) when the batch surfaced a NEW principal/identity, a coverage gap, \
or an artifact that contradicts the working hypothesis — those are exactly the \
moments to widen the look. A probe is read-only and cannot itself record a \
finding, so granting budget never risks evidence integrity.
ABSENCE-HYPOTHESIZE BEFORE TRANSITION: before you set transition_recommended=true \
to leave a non-Report phase, OR when the Triage max-pass cap is about to force a \
transition, FIRST put reason.hypothesize (mode="absence") at the front of \
priority_tools — observation = the still-unresolved part of the case question, \
evidence = the artifact categories already examined. It returns the untouched \
high-value categories (second-principal logon source, a different SID's profile, \
an alternate exfil channel, setupapi.dev.log) as probe candidates. This forces \
one divergent look before the funnel closes. Skip it only in Report.

IMPORTANT CONSTRAINTS:
- Atlas is a read-only forensic tool. Improve & Response actions are NEVER \
performed — they appear only as recommendations in the final report.
- The investigation begins with a confirmed positive detection already in hand. \
Start at Triage unless the stack says otherwise.
- You are a state machine, not a checklist. Any phase can transition to any other \
when evidence demands it.
- LINEAGE IS MANDATORY: every dair_assess, reason.*, record_finding, and \
record_self_correction call MUST pass input_call_ids=[<cid>, ...] listing the \
_atlas_call_id values of the entries that informed this step. The lineage_required \
gate refuses calls with empty input_call_ids after the first 5 trace entries \
(genesis grace). This makes the trace a self-describing causal DAG so the chain \
view and audit consumers can traverse real foreign keys, not heuristic guesses.

ACTIVE PHASES:
CASE-QUESTION ANCHORING: Every investigation has a case question stated in \
case_context as 'CASE_QUESTION: <one sentence>'. The initial Triage MUST run \
reason.hypothesize on the case question BEFORE reason.plan — the returned \
hypotheses become the testable propositions tracked across the investigation. \
DAIR's transition to Report is gated by reason.pre_report_check, which refuses \
ready_to_report unless at least one CONFIRMED or LIKELY finding directly \
addresses the case question's key entities.

KNOWNS-DRIVEN HUNTING: When case_context includes a reference set (suspect \
list, asset inventory, allowlist, baseline, hash list), include \
misc.knowns_pattern_generate followed by a knowns-IOC sweep \
(net.ngrep_search / strings.strings_grep / yara.scan_strings against the \
returned pattern) in the FIRST Triage batch — before generic enumeration.

DISCOVERY-FIRST PATHS: Never prescribe invented filenames, export names, or \
layouts. Authoritative discovery (misc.inventory_evidence, \
misc.list_evidence_dir, already_processed / catalog samples) overrides LLM \
assumptions. When the message carries a MOUNTED VOLUMES block, every path you \
prescribe on an image starts at the mount point it lists, followed by the rest \
of the path as the volume spells it; a profile is one of the directory names \
the block lists (or, when the block says names were left out, one a listing \
of that directory confirms), never a name taken from the brief; a root or a \
drive letter the block does not list is an invented path. A volume whose line says \
"baseline: analysis/baseline/<name>.json" has its operating system, install date, time zone, computer name, domain, registered \
owner, local accounts (SAM), profile list, interface addresses, network profiles, installed \
software, last shutdown and the USBSTOR device list on record as observations, read from \
SYSTEM, SOFTWARE, SAM and SECURITY: read them, cite them, never prescribe a hive parse to \
re-derive those. Everything else is parsed as usual (NTUSER.DAT, UsrClass.dat, MountPoints2, \
setupapi.dev.log, USB first and last connection times, any key the baseline does not list), \
and a baseline marked stale may be re-read. After discovery_first refusals, put those discovery tools at the \
front of priority_tools and drop speculative focus_paths. Do not treat \
invented-path failures as "evidence absent".

SCRIPT/PAYLOAD DEOBFUSCATION: For obfuscated scripts, maldocs, or encoded \
blobs (VBScript/JScript/PowerShell, .msc/.hta/.lnk, base64/hex/XOR payloads), \
prescribe the deob.* tools — deob.decode_chain, deob.powershell_decode, \
deob.base64_hunt, deob.xor_bruteforce, deob.hex_decode — plus misc.olevba_scan \
for Office macros. These are deterministic and citable; never rely on ad-hoc \
python one-liners via misc.batch_run for decoding, which are fragile and \
cannot be cited in a finding.

EMAIL/PHISHING EVIDENCE: When a .eml/.msg or mail store is in scope, put \
misc.parse_email FIRST — it returns reconciled headers (From vs Return-Path vs \
Reply-To vs Message-ID domain, plus SPF/DKIM/DMARC) and attachment hashes. The \
visible From: may be spoofed; attribute the attacker from the full header \
provenance. Distinguish the delivered attachment (the lure) from any file \
dropped/downloaded during execution (the second-stage payload) — hash each \
stage separately. A file that fails parse_email (not RFC822) is likely a \
native OLE .msg — retry with misc.parse_msg_ole; an Apple Mail store uses \
misc.parse_emlx. All three return the same shape. Non-Chrome browser history \
(Firefox/Safari) has no dedicated tool like misc.hindsight_chrome — use \
plaso.plaso_create_timeline with parsers="firefox_history,safari_history" \
scoped to the browser profile. For a lure link, resolve where it actually \
goes with enrich.urlscan_submit_scan (defaults to an unlisted, non-public \
scan) then enrich.urlscan_fetch_result for the final URL after redirects; \
enrich.vt_lookup_url is a lookup only, never submits an unseen URL — \
submitting one there is visible to other VirusTotal users and could tip off \
whoever controls the link. If a downloaded second-stage payload has a \
Zone.Identifier ADS (af_ads_enumeration lists these, filtered as benign), \
extract it and read it with af.af_zone_identifier_read for the HostUrl/ \
ReferrerUrl that proves which URL it came from.

  Triage   — confirm the initial IOC/alert AND actively challenge your own findings \
for hallucinations. Check file existence, registry key presence, process records, \
network connections. Every claim must be traceable to a specific tool output field \
and value. Produce an investigation plan via directives.priority_tools.
  Collect  — gather raw artifacts as directed by the Triage plan. Run ez.*, vol.*, \
tsk.*, strings.* tools. Stay until the plan is satisfied; advance to Analyze when \
sufficient evidence is in hand. \
EXHAUSTION RULE: for each artifact category named in the Triage plan (registry hives, \
event log channels, HTTP session cookies, memory regions, browser profiles), collect \
ALL instances of that category — not just the first one that yields results. Advance \
to Analyze only when every named category has been fully collected, not merely sampled. \
For network evidence: before advancing from Collect, run net.ngrep_search(pattern="Cookie:") \
and net.ngrep_search(pattern="(login|email|username|user=|gausr=|Y=|T=)") on each \
suspect device's traffic, plus net.tcpdump_extract_http and net.tcpxtract_streams. \
Cross-reference every found identity (email, username, screen name, cookie value) \
against any suspect list provided in case_context before advancing.
  Analyze  — reason about the collected artifacts: process trees, network \
connections, persistence mechanisms, TTPs. Each suspicious artifact should be \
examined. A genuinely ambiguous artifact may require more collection before \
proceeding. \
PIVOT CANDIDATES: if Analyze surfaces a reference to a host or principal other \
than the one under investigation — remote logon (4624 type 3/10), SMB session, \
mapped drive, inbound RDP, \\\\HOST\\share path in a command line or registry \
value, named pipe to a remote endpoint, newly-created account, or first-seen \
identity — treat it as a candidate pivot in your analysis. Do not assume that \
the phase stack must change automatically; prescribe explicit evidence-gathering \
tools only when the candidate matters to the case question. \
ALSO run anti-forensics detectors here when the relevant input artifacts exist: \
af.af_timestomp_drift (after ez.mftecmd CSV), af.af_event_log_clear (after \
ez.evtxecmd), af.af_sysmon_evasion (after ez.recmd_hive SYSTEM), af.af_usn_journal_deleted \
(after ez.mftecmd), af.af_prefetch_deletion (after ez.pecmd + \
ez.appcompatcacheparser/amcacheparser).

INAPPLICABLE TOOL SUBSTITUTION: If a priority_tools entry names a tool that \
cannot run against the available evidence type (e.g. ez.evtxecmd, ez.mftecmd, \
vol.pslist, tsk.fls on a PCAP-only case; net.tcpdump_read on a disk-only case), \
do NOT skip it silently and treat the work order as satisfied. Instead: \
(a) remove the inapplicable tool from the work order; \
(b) substitute the nearest equivalent for the actual evidence type — for Windows \
artifact tools on a PCAP case use net.ngrep_search or net.tcpdump_extract_http; \
(c) log the substitution as an agent_message. An empty work order after \
substitution means call dair_assess again for new priority_tools — not that \
collection is complete.

EVIDENCE-ABSENT WORK IS OUT OF SCOPE, NOT A REASON TO STAY: verify that a tool's \
required evidence actually exists before prescribing it. If the ONLY outstanding \
work needs an evidence type that is not present in this case (e.g. the brief \
mentions network activity but there is no PCAP, so net.* tools have nothing to \
read), do NOT keep re-prescribing those tools and staying in the phase. Mark that \
line of inquiry out-of-scope in transition_rationale and advance (stack_action \
"push") toward Report. A run that can never gather the missing evidence must still \
be able to reach Report and synthesize on what it does have. (The server enforces \
this: after repeated missing-file failures in one phase it will force the \
transition for you.)

IDENTITY RESOLUTION (mandatory before leaving Analyze): before recording any finding \
that states a real-world identity is unknown or unresolvable, verify that the Collect \
phase ran ALL identity-yielding tool categories for this evidence type. If any category \
was skipped, return stack_action "stay" and add the missing tools to priority_tools — \
do not advance to Scan or Report with an unresolved identity when evidence remains \
uncollected. Cross-referencing found identities against any suspect list in case_context \
is a required Analyze step, not optional enrichment.

LIVE ENDPOINT CASES: When case_context names a live endpoint (the agent will \
mention 'live=true' or supply an endpoint_host like 'ubuntu-endpoint' in case \
context), include live.* tools in priority_tools as appropriate:
  Triage   — live.live_processes, live.live_network_connections, live.live_recent_logins
  Collect  — live.live_persistence_audit, live.live_services, live.live_scheduled_tasks
  Analyze  — live.live_process_details(pid) and live.live_open_files(pid) for \
suspicious PIDs; live.live_event_log_tail(unit) for services of interest; \
live.live_read_file for small config artifacts (max 64KB cap)
  Scan     — live.live_yara_scan(rules_path, target_dir) for cross-host hunting
The live.* tools route through SSH with fixed argv (no remote shell parsing); \
findings can use their _atlas_call_id as linked_call_id like any other tool.
  Scan     — exhaustive cross-host IOC sweep and propagation check: \
yara.scan_directory across all collected disk/memory, net.tcpdump_extract_dns \
for exfil signatures, enrich.vt_lookup_hash and enrich.abuseipdb_check for \
hashes/IPs the agent had no earlier reason to look up. This phase is the \
safety net for IOCs the per-host Analyze passes did not surface. Candidate \
pivots discovered during Scan are advisory metadata; they do not create a \
server-enforced queue. Advance to Report when the cross-host sweep is exhausted \
and all case-relevant candidates have either been investigated or explicitly \
parked as out of scope / evidence unavailable.
  Report   — terminal phase unless report review exposes unresolved evidence. \
If reason.synthesize or reason.pre_report_check returns any BLOCKER / \
ready_to_report=false issue that asks for missing evidence, do NOT try to satisfy \
it by rephrasing findings. Prefer staying in Report and documenting a genuine \
dead-end via reason.synthesize UNRESOLVABLE when Access Stage already shows \
opened/access_failed or tsk open already failed — do NOT Report→Collect thrash \
for the same disk-open blocker (server-side damper will refuse the re-push). \
Only push Collect/Analyze when a NEW gatherable artifact is missing and tools \
can still acquire it. Put concrete missing tools in directives.priority_tools. \
For true dead-ends (tool cannot parse, artifact destroyed, privilege unavailable) \
state 'UNRESOLVABLE: <what> — <why>' in reason.synthesize once — do not spawn \
repeated UNCONFIRMED limitation findings. Only stay in Report for \
wording/citation cleanup when no missing-evidence blocker remains. BEFORE \
reason.synthesize, call BOTH \
coverage.coverage_report (TTP coverage checklist) AND attribution.attribute_actors \
(adversary attribution from observed T-IDs) so the final synthesis input has the \
complete picture. When findings span multiple hosts, ALSO call \
correlate.process_to_file and correlate.network_to_process (with no PID/IP/path \
filter, to get the full cross-host join) so the synthesis input has real \
cross-host joins rather than isolated per-host slices. Then synthesise findings \
into a timeline. Emit Improve & Response recommendations for the IR team in \
recommended_actions. Never direct containment or eradication tool calls.

PHASE STACK:
The phase_stack is the investigation phase history. Newest entry is last. \
Use it to understand depth and context. Candidate pivots are separate metadata; \
they do not automatically add Triage frames.
  stack_action "push"  → transition to next_phase; new entry added to stack
  stack_action "pop"   → current sub-phase resolved; resume the phase beneath
  stack_action "stay"  → continue in current_phase (e.g. challenges still pending)

VERIFICATION CHALLENGES (mandatory when current_phase == Triage):
For every discrete claim in the tool results summary, emit a challenge entry:
  - claim: the exact claim (file path, registry key, process name, IP, etc.)
  - challenge_method: the specific Atlas tool that confirms it \
(strings.stat_file, tsk.fls, vol.pslist, ez.recmd_hive, vol.netscan, etc.)
  - verified: null if the tool has not yet run; true if tool output confirms; \
false if tool output refutes
  - confidence_impact: tier downgrade string if verified is false (e.g. \
"CONFIRMED → SUSPECTED"); "—" if verified is true or null
  - notes: what the tool found, or why the claim cannot be verified
When verified is null, the challenge_method tool MUST appear in \
directives.priority_tools so it runs in the next batch.
If any challenge resolves to false, that claim must be downgraded or removed \
before advancing to Collect.
In Collect, Analyze, or Scan phases, VERIFICATION_CHALLENGES may be omitted \
unless a specific claim needs active challenging.

TRIAGE SATISFACTION:
Set verification_satisfied=true when the primary IOCs are confirmed or refuted \
to a sufficient evidential standard, even if some secondary challenges remain \
pending. Criteria for satisfaction:
  - All load-bearing claims (file existence, process identity, network connection \
    attribution) have verified=true or verified=false.
  - Remaining verified=null entries are enrichment-only (VT lookups, timestamp \
    cross-checks, attribution details) — they add confidence but are not required \
    to establish the core compromise.
  - Re-running the same challenge category for the third or more time yields \
    diminishing returns (no new material pivots).
When verification_satisfied=true, set transition_recommended=true, \
next_phase="Collect", and stack_action="push". Do not keep the investigation in \
Triage indefinitely — acceptable residual uncertainty is normal.


OUTPUT FORMAT:
Write your analysis first — keep it UNDER 60 WORDS. The structured blocks \
below carry the decision; long free-text deliberation burns the output budget \
and risks truncating the blocks (reasoning backends already spend thousands \
of tokens before emitting content). Then output the structured blocks in \
this order:

If current_phase is Triage, output VERIFICATION_CHALLENGES first:
VERIFICATION_CHALLENGES:
[
  {
    "claim": "...",
    "challenge_method": "strings.stat_file",
    "verified": null,
    "confidence_impact": "—",
    "notes": ""
  }
]

Then always output DAIR_ASSESSMENT (no markdown bold, no code fences, no // comments):
DAIR_ASSESSMENT:
{
  "current_phase": "Triage",
  "phase_rationale": "...",
  "transition_recommended": false,
  "next_phase": "",
  "transition_rationale": "",
  "stack_action": "stay",
  "investigation_focus": "...",
  "verification_satisfied": false,
  "verification_challenges": [],
  "recommended_actions": [],
  "directives": {
    "priority_tools": [],
    "skip_tools": [],
    "focus_pids": [],
    "focus_paths": [],
    "max_depth": "",
    "next_hypothesis_triggers": [],
    "curiosity_budget": 0
  },
  "deferred_intent_dispositions": []
}

verification_challenges in DAIR_ASSESSMENT must mirror VERIFICATION_CHALLENGES block \
exactly when in Triage phase. recommended_actions is populated ONLY when \
transitioning to Report — list specific Improve & Response actions for the IR team. \
Tool names in directives must use Atlas MCP format: namespace.tool and must \
come from the Tool Capability Manifest below. \
Remember: priority_tools is the investigator's complete work order for this batch. \
Make it specific and executable — every entry will be run before you see results.

DEFERRED INTENTS (when the DEFERRED INTENTS block appears in the user message):
These are forensic probes the investigator attempted while the DAIR batch window
was cold (or while the deferred backlog latch was set). They were NOT executed.
For EVERY open deferred intent you MUST emit an entry in
deferred_intent_dispositions inside DAIR_ASSESSMENT:
  {"call_id": <id>, "action": "promote"|"dismiss"|"keep", "note": "<why>"}
- promote: still relevant → include its priority_hint in directives.priority_tools
  so it runs in this batch. Prefer promote when the probe could answer
  investigation_focus or an open hypothesis.
- dismiss: no longer relevant / duplicate / superseded → drop it.
- keep: leave open without running (rare; does not relieve backlog pressure).
When the backlog latch warning is present, you MUST reduce open intents
(promote and/or dismiss) — keeping everything open stalls the investigation.
"""

_DAIR_SYS = _DAIR_SYS + "\n\n" + format_tool_manifest_for_prompt()


def _state_signature(phase: str, stack_depth: int) -> dict:
    """What an assessment is a function of: the phase and stack, the
    findings and the evidence they cite, hypotheses raised and confirmed,
    corrections, report readiness, the evidence classes present and the
    deferred probes awaiting a ruling. JSON-native, so a value read back
    from a rehydrated trace compares equal to a freshly computed one."""
    from core import progress_signature as _prog
    from core.execution_log import log as _elog
    snap = _prog.snapshot("cheap")
    entries = list(_elog._entries)
    classes: list[str] = []
    try:
        case = _case_root()
        if case:
            from core.evidence_profile import ensure_evidence_profile
            classes = sorted(
                (ensure_evidence_profile(case) or {}).get("present_classes") or [])
    except Exception:  # noqa: BLE001
        classes = []
    try:
        open_deferred = sum(1 for e in _elog.open_deferred_intents()
                            if e.get("status") == "open")
    except Exception:  # noqa: BLE001
        open_deferred = 0
    # A mount made mid-run changes what the director is told; an assessment
    # made without the block must not stand for one made with it.
    try:
        from core.mount_plan import mounted_volumes
        mounts = sorted(v.get("rel") or v.get("device_rel") or ""
                        for v in (mounted_volumes(case) if case else []))
    except Exception:  # noqa: BLE001
        mounts = []
    gaps = _gaps_digest()
    return {
        "phase": str(phase),
        "stack_depth": int(stack_depth),
        "mounts": [m for m in mounts if m],
        "unread": gaps["unread"],
        "open_parts": gaps["open_parts"],
        "findings": sorted(snap.finding_ids),
        "evidence_refs": sorted(snap.evidence_ref_ids),
        "confirmed_hypotheses": sorted(snap.confirmed_hypothesis_ids),
        "hypotheses": sum(1 for e in entries
                          if e.get("type") == "reason_call" and e.get("hypothesis_id")),
        "corrections": sum(1 for e in entries if e.get("type") == "self_correction"),
        "ready_to_report": bool(snap.ready_to_report),
        "evidence_classes": [str(c) for c in classes],
        "open_deferred": int(open_deferred),
    }


def _standing_assessment(signature: dict) -> dict | None:
    """The newest recorded assessment when it was made on this very state
    and can stand for it: a model reply (not the empty template) that kept
    the phase, past Triage (whose challenges every batch answers), with no
    deferred probe awaiting a ruling, no tool call failed since it was made,
    and standing for fewer than _REUSE_MAX_CONSECUTIVE calls already. None
    means consult the director."""
    if (not DAIR_REUSE_STANDING or signature.get("phase") == "Triage"
            or signature.get("open_deferred")):
        return None
    try:
        from core.execution_log import log as _elog
        entries = list(_elog._entries)
    except Exception:  # noqa: BLE001
        return None
    newest = None
    reused = 0
    for i in range(len(entries) - 1, -1, -1):
        e = entries[i]
        if e.get("type") != "dair_call":
            continue
        # A failed call since the newest assessment leaves the state as it
        # was, so the signature cannot see it; the director has to read the
        # failure. A call the run's own stop cut short (marked interrupted)
        # is no failure of the work order.
        if newest is None and any(
                x.get("type") == "tool_call" and x.get("success") is False
                and not x.get("interrupted")
                for x in entries[i + 1:]):
            return None
        inputs = e.get("inputs") or {}
        if (inputs.get("state_signature") != signature
                or e.get("current_phase") != signature["phase"]
                or e.get("stack_action") != "stay"
                or not e.get("phase_rationale")):
            return None
        if newest is None:
            newest = e
        if not inputs.get("reused_from_call_id"):
            break  # the assessment the chain stands on
        reused += 1
    if newest is None or reused >= _REUSE_MAX_CONSECUTIVE:
        return None
    return newest


# ── MCP tool ──────────────────────────────────────────────────────────────────

def _recent_repeat_rate(window: int = 40) -> str:
    """One line on how much recent tool output the run had already obtained.

    The empty-loop valve catches an *identical* work order. A varied one that
    keeps re-deriving answers the run already holds is invisible to it, and
    to the call memo as well: the memo keys on the question, and these ask
    different questions to receive the same answer. The signal is the share
    of calls whose output hash was already seen.

    Reported, never acted on — the phase decision stays the director's. Silent
    below a floor of calls and below a rate worth mentioning, so a healthy
    pass carries no extra text.
    """
    from core.execution_log import log as _elog
    calls = [e for e in getattr(_elog, "_entries", [])
             if e.get("type") == "tool_call" and e.get("output_hash")]
    if len(calls) < 12:
        return ""
    recent = calls[-window:]
    seen = {e.get("output_hash") for e in calls[:-len(recent)]}
    dup = 0
    for e in recent:
        h = e.get("output_hash")
        if h in seen:
            dup += 1
        seen.add(h)
    if dup * 100 < len(recent) * 40:
        return ""
    return ("REPEATED OUTPUT: %d of the last %d tool calls returned output "
            "this run had already obtained. Judge whether this line of "
            "enquiry is still producing, or whether the phase should move on."
            % (dup, len(recent)))


def _report_gate_block(entries) -> str:
    """The latest ``reason.pre_report_check`` verdict as a block for the
    director, empty when the gate was never consulted. The gate decides
    whether the report may be written; in Report the director's work order
    is whatever that verdict still lists."""
    from core.execution_log import as_text
    last = None
    for e in entries or []:
        if (isinstance(e, dict) and e.get("type") == "reason_call"
                and e.get("tool") == "reason_pre_report_check"):
            last = e
    if last is None:
        return ""
    text = as_text(last.get("conclusion")).strip()[:1500]
    if not text:
        return ""
    return (f"REPORT GATE (latest reason.pre_report_check, call #{last.get('call_id')}):\n"
            f"{text}")


@mcp.tool()
def dair_assess(
    tool_results_summary: str,
    phase_stack: str | list | None = "[]",
    case_context: str = "",
    input_call_ids: list[int] | None = None,
    fresh: bool = False,
) -> dict:
    """
    Assess the current DAIR phase, challenge findings, and direct the next steps.
    Call this after every parallel tool batch, and at each phase transition.
    When nothing recorded has changed since the last assessment (no new
    finding, evidence, hypothesis, correction, evidence class or deferred
    probe, same phase) the standing assessment is returned again instead of
    consulting the director; pass fresh=true to consult it regardless.

    tool_results_summary: 3-5 sentence summary of what the last tool batch found.
    phase_stack: JSON list of {phase, entry_reason, depth} objects, newest last.
                 Pass "[]" on the first call — DAIR will start at Triage.
    case_context: case ID, the analyst's PRIOR KNOWLEDGE statements that
                  bear on this batch, known threat actor, confirmed IOCs so far.
    input_call_ids: optional — the _atlas_call_id values of the calls whose
        results you summarised. Omit it and every tool and reason call since
        the previous assessment is taken as the lineage; never abbreviate a
        list.

    Returns: current_phase, phase_rationale, transition_recommended, next_phase,
             transition_rationale, stack_action, investigation_focus,
             verification_challenges (when in Triage), recommended_actions
             (when transitioning to Report), directives, _atlas_call_id.

    stack_action "push"  → append {phase: next_phase, entry_reason, depth} to stack
    stack_action "pop"   → remove top entry; resume parent phase
    stack_action "stay"  → no change to stack

    Cycle: Triage → Collect → Analyze → Scan → Report. Candidate hosts or
    principals may be returned in candidate_pivots, but they are advisory
    observations and do not alter stack_action or next_phase.

    When stack_action is "push" and next_phase is "Triage": check
    verification_challenges for entries with verified=null and run the specified
    challenge_method tools (they will be in directives.priority_tools).

    When next_phase is "Report": review recommended_actions for Improve & Response
    items to include in the report. These are advisory only — Atlas never performs
    containment or eradication.
    """
    summary = _cap_lines(tool_results_summary.strip(), 100)
    # Summary-vs-trace verification: the agent's tool_results_summary is
    # LLM-authored and was observed carrying entirely fabricated results
    #.
    # DAIR plans on this text, so a fabricated summary corrupts the whole
    # next batch. Flag tool mentions that never executed.
    fabricated = _summary_fabricated_tools(summary)
    if fabricated:
        summary = (
            "[summary-verification] The following tools were NEVER executed "
            f"in this run: {', '.join(sorted(fabricated))}. Any results the "
            "summary attributes to them are fabricated — disregard those "
            "claims and do not plan follow-ups on them.\n" + summary
        )
        try:
            from core.execution_log import log as _velog
            _velog.record_agent_message(
                "[dair summary-verification] fabricated tool mentions: "
                + ", ".join(sorted(fabricated)))
        except Exception:
            pass
    context = _cap_lines(case_context.strip(), 50) if case_context else ""

    # Models often send phase_stack as a native list; schema historically
    # asked for a JSON string. Accept both (toolbox also coerces pre-validate).
    if isinstance(phase_stack, list):
        stack = phase_stack
        stack_str = json.dumps(phase_stack, ensure_ascii=False)
    else:
        stack_str = (phase_stack or "").strip() or "[]"
        try:
            stack = json.loads(stack_str)
            if not isinstance(stack, list):
                stack = []
        except (json.JSONDecodeError, ValueError):
            stack = []

    # Prefer the execution-log stack (sole authority) over the agent-supplied
    # phase_stack string, which can lag a valve push and re-open Collect thrash.
    log_phase = _log_stack_phase()
    current = log_phase or (
        stack[-1].get("phase", "Triage") if stack else "Triage"
    )
    if log_phase and stack and stack[-1].get("phase") != log_phase:
        stack = list(stack)
        stack[-1] = {**dict(stack[-1]), "phase": log_phase}

    # The mounted volumes go first: the last-rung compaction keeps the head
    # and the tail of the message, and a block after the case context can
    # fall into the dropped middle.
    user_parts = []
    _mounts = _mounted_volumes_block()
    if _mounts:
        user_parts.append(_mounts + "\n")
    _gaps = _gaps_block()
    if _gaps:
        user_parts.append(_gaps + "\n")
    user_parts.append(f"TOOL RESULTS SUMMARY:\n{summary}")
    user_parts.append(f"\nCURRENT PHASE STACK (newest last):\n{json.dumps(stack, indent=2)}")
    user_parts.append(f"\nCURRENT PHASE: {current}")
    if context:
        user_parts.append(f"\nCASE CONTEXT:\n{context}")

    # The report gate's own verdict, not the investigator's account of it:
    # a summary that called the blockers closed while the gate still
    # listed them was believed, and the director prescribed nothing.
    try:
        from core.execution_log import log as _elog
        _gate = _report_gate_block(_elog._entries)
        if _gate:
            user_parts.append("\n" + _gate)
    except Exception:  # noqa: BLE001
        pass

    # What the director cannot otherwise see: how much of its recent work is
    # re-deriving answers the run already holds.
    try:
        _repeat = _recent_repeat_rate()
        if _repeat:
            user_parts.append("\n" + _repeat)
    except Exception:  # noqa: BLE001
        pass

    # Surface deferred forensic intents so DAIR can promote/dismiss them.
    deferred_block = ""
    try:
        from core.deferred_intents import format_open_intents_for_dair
        from core.execution_log import log as _elog
        _open = [
            e for e in _elog.open_deferred_intents()
            if e.get("status") == "open"
        ]
        _st = _elog.deferred_backlog_status()
        deferred_block = format_open_intents_for_dair(
            _open, latched=bool(_st.get("latched")))
        if deferred_block:
            user_parts.append("\n" + deferred_block)
    except Exception as _def_err:
        import sys as _sys
        print(f"[Atlas WARN] deferred intent inject failed: {_def_err!r}",
              file=_sys.stderr)

    user = "\n".join(user_parts)

    # Capture exactly what was sent to the DAIR model so the trace can be
    # audited by judges or replayed later.
    lineage_derived = False
    if not input_call_ids:
        # An omitted list means what a complete one would have said: every
        # call since the previous assessment. A model asked to enumerate
        # thousands of ids abbreviates or fills ranges; the log knows them.
        try:
            from core.execution_log import log as _elog
            input_call_ids = _elog.call_ids_since_last("dair_call") or None
            lineage_derived = bool(input_call_ids)
        except Exception:  # noqa: BLE001 - no log, no lineage to derive
            input_call_ids = None
    else:
        # A list given is bounded against the ids the run has issued before
        # the director is consulted on it.
        from core.execution_log import log as _elog
        from tools._gates import lineage_required
        refusal = lineage_required.check_ids(_elog, input_call_ids)
        if refusal is not None:
            return refusal
    call_inputs = {
        "tool_results_summary": summary,
        "phase_stack": stack,
        "case_context": context,
        "current_phase": current,
        "tool_manifest_version": MANIFEST_VERSION,
        "user_message": user,
    }
    if deferred_block:
        call_inputs["deferred_intents_injected"] = True
    if lineage_derived:
        call_inputs["lineage_derived"] = len(input_call_ids or [])

    # Assess on change: the state this call is made on is recorded with it,
    # and a call made on the very state the newest assessment was made on
    # gets that assessment back. Fail-open — a signature problem costs a
    # director call, never an assessment.
    standing = None
    try:
        call_inputs["state_signature"] = _state_signature(current, len(stack))
        if not fresh:
            standing = _standing_assessment(call_inputs["state_signature"])
    except Exception as _sig_err:
        import sys as _sys
        print(f"[Atlas WARN] dair state signature failed: {_sig_err!r}",
              file=_sys.stderr)
    if standing is not None:
        call_inputs["reused_from_call_id"] = int(
            (standing.get("inputs") or {}).get("reused_from_call_id")
            or standing.get("call_id") or 0)
        backend_result = {"success": True, "raw": "",
                          "input_tokens": 0, "output_tokens": 0}
    else:
        backend_result = _ask(_DAIR_SYS, user)

    _empty_result = {
        **_EMPTY_ASSESSMENT,
        "directives": _parse_directives(""),
        "success": False,
        "input_tokens": 0,
        "output_tokens": 0,
    }

    if not backend_result.get("success"):
        err = backend_result.get("error", "unknown error")
        result = {**_empty_result, "error": err}
        if backend_result.get("reply_cut"):
            call_inputs = {**call_inputs, "reply_cut": backend_result["reply_cut"]}
        _log_dair(_EMPTY_ASSESSMENT | {"directives": _parse_directives("")}, 0, 0,
                  inputs=call_inputs, input_call_ids=input_call_ids)
        result["_atlas_call_id"] = 0
        return result

    raw = backend_result["raw"]
    if standing is not None:
        # The standing decision and work order, copied out of the trace;
        # the manifest annotations are re-derived below like any reply.
        challenges = []
        assessment = {k: copy.deepcopy(standing.get(k, v))
                      for k, v in _EMPTY_ASSESSMENT.items()}
        held = standing.get("directives") or {}
        assessment["directives"] = {k: copy.deepcopy(held.get(k, v))
                                    for k, v in _EMPTY_DIRECTIVES.items()}
    else:
        challenges = _parse_challenges(raw)
        assessment = _parse_dair_assessment(raw)

    # challenges from dedicated block take precedence over those embedded in assessment
    if challenges:
        assessment["verification_challenges"] = challenges

    # Pin current_phase to the authoritative log/stack value. The model may
    # echo a stale phase; valves and work-order enforcement must not follow it.
    if current:
        assessment["current_phase"] = current

    candidate_pivots: list[dict] = []

    # Cross-phase pivot observation. Any non-Triage phase may surface a host or
    # principal worth follow-up, but this metadata must not rewrite the DAIR
    # transition. The caller can inspect candidate_pivots and decide whether to
    # investigate; the state machine remains model/agent-directed.
    if current in _PIVOT_ELIGIBLE_PHASES:
        summary_hosts = _extract_host_tokens(summary)
        known_hosts = _build_known_host_set(context)
        for h in sorted(summary_hosts - known_hosts):
            candidate_pivots.append({
                "kind": "host",
                "value": h,
                "source": "tool_results_summary",
                "phase": current,
            })

        # A previously-unseen *principal* is also a follow-up candidate. The
        # cue tier is preserved for audit/debugging, not control flow.
        known_principals = _build_known_principal_set(context)
        forced_principals = sorted(
            _extract_principal_tokens(summary, cue="forced") - known_principals
        )
        appearance_principals = sorted(
            _extract_principal_tokens(summary, cue="appearance")
            - known_principals - set(forced_principals)
        )
        for p in forced_principals:
            candidate_pivots.append({
                "kind": "principal",
                "value": p,
                "source": "tool_results_summary",
                "phase": current,
                "cue": "forced",
            })
        for p in appearance_principals:
            candidate_pivots.append({
                "kind": "principal",
                "value": p,
                "source": "tool_results_summary",
                "phase": current,
                "cue": "appearance",
            })

    # Guard: if all triage challenges resolved true but the assessment JSON failed
    # to parse (phase_rationale empty = _EMPTY_ASSESSMENT fallback), auto-satisfy.
    if (
        assessment.get("current_phase") == "Triage"
        and not assessment.get("verification_satisfied")
        and assessment.get("stack_action") == "stay"
    ):
        _ch = assessment.get("verification_challenges", [])
        if _ch and all(c.get("verified") is not None for c in _ch) \
                and all(c.get("verified") is not False for c in _ch):
            assessment["verification_satisfied"] = True
            assessment["transition_recommended"] = True
            assessment["next_phase"] = "Collect"
            assessment["stack_action"] = "push"
            if not assessment.get("transition_rationale"):
                assessment["transition_rationale"] = (
                    "Auto-satisfied: all verification challenges confirmed"
                )

    # directives come from inside the DAIR_ASSESSMENT JSON block; ensure they have
    # all required keys by merging with the empty template via _parse_directives
    embedded = assessment.get("directives")
    if isinstance(embedded, dict) and embedded:
        raw_directives = {**_EMPTY_DIRECTIVES, **embedded}
    else:
        raw_directives = _parse_directives(raw)

    # Deterministic safety net: never let an active phase leave with an empty
    # work order, and enforce the Triage max-pass cap server-side. This mutates the transition fields on `assessment`.
    final_tools, enforcement_note = _enforce_work_order(
        assessment, raw_directives, summary, context)
    # Never prescribe tools whose required evidence classes are absent — the
    # execution gate would refuse them anyway; refusing at plan time saves
    # the wasted turn and the compat-refusal noise.
    final_tools, _dropped = _filter_inapplicable_tools(final_tools)
    if _dropped:
        assessment["inapplicable_tools_dropped"] = _dropped
        if not final_tools:
            # Re-fill rather than emit an empty work order.
            final_tools = _default_work_order(
                context, summary, evidence_blob=_evidence_blob())
            final_tools, _ = _filter_inapplicable_tools(final_tools)
            enforcement_note = enforcement_note or "inapplicable_refill"
    raw_directives["priority_tools"] = final_tools
    if enforcement_note:
        assessment["work_order_enforced"] = enforcement_note

    # Apply deferred-intent dispositions from the DAIR model; promote tools
    # into the work order. Remaining backlog above hysteresis is auto-relieved
    # so a full latch can never deadlock the run.
    try:
        from core.execution_log import log as _elog
        dispositions = assessment.get("deferred_intent_dispositions")
        if not isinstance(dispositions, list):
            dispositions = []
        disp_result = _elog.apply_deferred_dispositions(dispositions, dair_cid=0)
        for pt in disp_result.get("promoted_tools") or []:
            if pt and pt not in raw_directives["priority_tools"]:
                raw_directives["priority_tools"].append(pt)
        assessment["deferred_disposition_result"] = {
            "applied": disp_result.get("applied"),
            "open_count": disp_result.get("open_count"),
            "latched": disp_result.get("latched"),
        }
        st = _elog.deferred_backlog_status()
        if st.get("latched") and st.get("open", 0) > st.get("hysteresis", 7):
            relieved = _elog.relieve_deferred_backlog(
                reason="post_assess_backlog_pressure")
            assessment["deferred_backlog_relieved"] = relieved
    except Exception as _disp_err:
        import sys as _sys
        print(f"[Atlas WARN] deferred disposition apply failed: "
              f"{_disp_err!r}", file=_sys.stderr)

    # Findings nudge: if the investigation has run many tools but recorded few
    # findings, tell the agent to formalise confirmed observations now. Not applicable in Report.
    if assessment.get("current_phase") != "Report" and _findings_lagging():
        actions = list(raw_directives.get("required_actions") or [])
        if _FINDINGS_NUDGE not in actions:
            actions.insert(0, _FINDINGS_NUDGE)
        raw_directives["required_actions"] = actions
        assessment["findings_nudge"] = True

    #: task disposition after valid tabular contact — prefer claims/
    # task updates over expensive disk-open while CASE tasks stay open.
    # Demoting disk work behind claims and tabular queries is a nudge for a
    # run that has opened its images and is slow to record; while a disk
    # image is still unseen it would keep the primary evidence out of the
    # work order and leave the run on one tabular source for many turns.
    if (assessment.get("current_phase") != "Report"
            and _task_disposition_lagging()
            and not _disk_units_unseen()):
        actions = list(raw_directives.get("required_actions") or [])
        if _TASK_DISPOSITION_NUDGE not in actions:
            actions.insert(0, _TASK_DISPOSITION_NUDGE)
        raw_directives["required_actions"] = actions
        raw_directives["priority_tools"] = _deprioritize_expensive_disk(
            list(raw_directives.get("priority_tools") or []))
        assessment["task_disposition_nudge"] = True

    # TTP nudge: put ATT&CK mapping INSIDE the Analyze loop instead of at the
    # report boundary. priority_tools is the work order the analyst actually
    # executes, so mitre_map/coverage_report ride along with the batch.
    if (assessment.get("current_phase") != "Report"
            and _ttp_mapping_lagging(
                assessment.get("current_phase") or "",
                assessment.get("next_phase") or "")):
        actions = list(raw_directives.get("required_actions") or [])
        if _TTP_NUDGE not in actions:
            actions.append(_TTP_NUDGE)
        raw_directives["required_actions"] = actions
        ptools = list(raw_directives.get("priority_tools") or [])
        for t in ("correlate.mitre_map", "coverage.coverage_report"):
            if t not in ptools:
                ptools.append(t)
        raw_directives["priority_tools"] = ptools
        assessment["ttp_nudge"] = True

    assessment["directives"] = annotate_directives_with_manifest(raw_directives)

    tok_in  = backend_result.get("input_tokens", 0)
    tok_out = backend_result.get("output_tokens", 0)
    call_id = _log_dair(assessment, tok_in, tok_out, inputs=call_inputs,
                        input_call_ids=input_call_ids,
                        candidate_pivots=candidate_pivots)

    # Internal-only: the raw knowledge-state snapshot was needed by _log_dair
    # (record_dair_call stores it so the NEXT cycle can diff against it) but
    # the raw ID sets are noise to the LLM — drop it before building the
    # result. assessment["progress"] (the explainable delta: changed/reasons/
    # changed_dimensions) stays visible — it tells the agent WHY DAIR did or
    # didn't force a transition.
    assessment.pop("_progress_snapshot", None)

    result = {
        **assessment,
        "success": True,
        "input_tokens": tok_in,
        "output_tokens": tok_out,
        "_atlas_call_id": call_id,
    }
    if call_inputs.get("reused_from_call_id"):
        result["reused_from_call_id"] = call_inputs["reused_from_call_id"]
    if candidate_pivots:
        result["candidate_pivots"] = candidate_pivots
    return result
