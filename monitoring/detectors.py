"""Central detector registry — the single source of truth for every
``Custom.Atlas.*`` live-monitoring detector.

Before this module the watcher (``bin/atlas-velo-watcher.py``) carried four
parallel hardcoded tables keyed on the detector name — pivot tools, dedup
signature fields, one-line summary, and severity — and ``tools/monitor.py`` /
``monitoring/render.py`` separately encoded which artifacts to baseline and
which templates to push. Adding a detector meant editing all of those in
lock-step, and nothing knew a detector's target OS, so ``start_watcher`` would
happily push Linux templates at a Windows client.

This registry collapses that into one ``DetectorSpec`` per detector plus a few
pure lookup helpers. It is **stdlib-only** on purpose: the standalone watcher
imports it directly, so it must not drag in MCP / FastMCP / velo.

Unknown detectors (e.g. an operator hand-pushing an artifact not in the table)
degrade gracefully — every helper returns the pre-registry default so the
watcher keeps working.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Optional


def _resolve(row: dict, *keys: str):
    """First truthy value among ``keys`` (``or`` semantics), else ""."""
    for k in keys:
        v = row.get(k)
        if v:
            return v
    return ""


@dataclass(frozen=True)
class DetectorSpec:
    """Everything the framework needs to know about one live detector.

    platform:        "linux" | "windows" (which client OS it targets).
    severity:        alert severity string.
    signature_keys:  ordered list of natural-key groups; each group is a tuple
                     of alternative row keys tried in order. The dedup
                     signature is these resolved values joined with "|".
    summary:         callable(row) -> one-line human description.
    pivots:          advisory pivot tools handed to the agent on an alert.
    requires:        host-side dependencies (e.g. "sysmon"); advisory only.
    template_stem:   artifact template file stem, if it differs from the name.
    synthetic:       True for Python-side behavior rules (monitoring/behavior.py)
                     that have no Velociraptor template and are never pushed to a
                     client — they are generated in the watcher from streamed rows.
    """

    platform: str
    severity: str
    signature_keys: tuple[tuple[str, ...], ...]
    summary: Callable[[dict], str]
    pivots: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()
    template_stem: Optional[str] = None
    synthetic: bool = False


# ── The registry ────────────────────────────────────────────────────────────
#
# Keyed by artifact name. Keep summaries byte-for-byte equal to the strings the
# watcher used to emit so alert consumers and snapshot tests don't shift.

DETECTORS: dict[str, DetectorSpec] = {
    "Custom.Atlas.NewProcess": DetectorSpec(
        platform="linux",
        severity="high",
        # image+pid identify a process; PID can be reused across respawn, so
        # started_utc is folded in when present.
        signature_keys=(("image_path",), ("pid",), ("started_utc",)),
        summary=lambda r: (
            f"New process not in baseline: "
            f"{r.get('image_path', '?')} (pid={r.get('pid', '?')})"
        ),
        pivots=(
            "velo.collect_artifact(Linux.Sys.Pslist)",
            "velo.collect_artifact(Linux.Sys.ProcessOpenFiles)",
            "velo.collect_artifact(Linux.Network.Netstat)",
            "yara.scan_strings",
        ),
    ),
    "Custom.Atlas.NewPersistence": DetectorSpec(
        platform="linux",
        severity="medium",
        # Mtime in the signature so a *changed* persistence file refires.
        signature_keys=(("path",), ("mtime_utc",)),
        summary=lambda r: f"New persistence entry: {r.get('path', '?')}",
        pivots=(
            "velo.collect_artifact(Linux.Sys.SystemdUnits)",
            "velo.collect_artifact(Linux.Sys.Crontab)",
            "velo.query(SELECT FullPath, Size, Mtime FROM stat(filename=<path>))",
        ),
    ),
    "Custom.Atlas.NewNetwork": DetectorSpec(
        platform="linux",
        severity="medium",
        signature_keys=(("remote_ip",), ("remote_port",), ("Pid", "pid")),
        summary=lambda r: (
            f"New outbound connection: "
            f"{r.get('remote_ip', '?')}:{r.get('remote_port', '?')} "
            f"(pid={r.get('Pid') or r.get('pid', '?')})"
        ),
        pivots=(
            "velo.collect_artifact(Linux.Network.Netstat)",
            "velo.collect_artifact(Linux.Sys.Pslist)",
            "enrich.abuseipdb_check",
        ),
    ),
    "Custom.Atlas.YaraProcess": DetectorSpec(
        platform="linux",
        severity="high",
        signature_keys=(("pid",), ("rule",)),
        summary=lambda r: (
            f"YARA hit {r.get('rule', '?')!r} on process "
            f"{r.get('process_name', '?')} (pid={r.get('pid', '?')})"
        ),
        pivots=(
            "velo.collect_artifact(Linux.Sys.Pslist)",
            "velo.collect_artifact(Generic.Forensic.LocalHashes.Glob)",
            "yara.scan_strings",
        ),
    ),

    # ── Windows detectors (Sysmon-backed; see requires) ──────────────────────
    "Custom.Atlas.WinNewProcess": DetectorSpec(
        platform="windows",
        severity="high",
        # image+pid identify a process; started_utc folds in respawn.
        signature_keys=(("image_path",), ("pid",), ("started_utc",)),
        summary=lambda r: (
            f"New Windows process not in baseline: "
            f"{r.get('image_path', '?')} (pid={r.get('pid', '?')})"
        ),
        pivots=(
            "velo.collect_artifact(Windows.System.Pslist)",
            "velo.collect_artifact(Windows.Sys.Handles)",
            "velo.collect_artifact(Windows.Network.Netstat)",
            "yara.scan_strings",
        ),
        requires=("sysmon",),
    ),
    "Custom.Atlas.WinNewPersistence": DetectorSpec(
        platform="windows",
        severity="medium",
        signature_keys=(("path",), ("mtime_utc",)),
        summary=lambda r: f"New Windows persistence entry: {r.get('path', '?')}",
        pivots=(
            "velo.collect_artifact(Windows.Sys.StartupItems)",
            "velo.collect_artifact(Windows.System.Services)",
            "velo.collect_artifact(Windows.System.TaskScheduler)",
        ),
    ),
    "Custom.Atlas.WinNewNetwork": DetectorSpec(
        platform="windows",
        severity="medium",
        signature_keys=(("remote_ip",), ("remote_port",), ("Pid", "pid")),
        summary=lambda r: (
            f"New Windows outbound connection: "
            f"{r.get('remote_ip', '?')}:{r.get('remote_port', '?')} "
            f"(pid={r.get('Pid') or r.get('pid', '?')})"
        ),
        pivots=(
            "velo.collect_artifact(Windows.Network.Netstat)",
            "velo.collect_artifact(Windows.System.Pslist)",
            "enrich.abuseipdb_check",
        ),
        requires=("sysmon",),
    ),

    # ── DNS + failed-auth detectors (increment 8) ────────────────────────────
    "Custom.Atlas.WinDnsQuery": DetectorSpec(
        platform="windows",
        severity="medium",
        signature_keys=(("query_name",), ("pid",)),
        summary=lambda r: (
            f"DNS query: {r.get('query_name', '?')} "
            f"from {r.get('image_path', '?')} (pid={r.get('pid', '?')})"
        ),
        pivots=(
            "enrich.vt_lookup_domain",
            "enrich.passive_dns",
            "velo.collect_artifact(Windows.System.Pslist)",
        ),
        requires=("sysmon",),
    ),
    "Custom.Atlas.AuthFailures": DetectorSpec(
        platform="linux",
        severity="medium",
        signature_keys=(("source_ip",), ("user",)),
        summary=lambda r: (
            f"Auth failure: user {r.get('user', '?')} from {r.get('source_ip', '?')}"
        ),
        pivots=(
            "enrich.abuseipdb_check",
            "velo.collect_artifact(Linux.Sys.LastUserLogin)",
        ),
    ),
    "Custom.Atlas.WinAuthFailures": DetectorSpec(
        platform="windows",
        severity="medium",
        signature_keys=(("source_ip",), ("user",)),
        summary=lambda r: (
            f"Windows logon failure: user {r.get('user', '?')} "
            f"from {r.get('source_ip', '?')}"
        ),
        pivots=(
            "enrich.abuseipdb_check",
            "velo.collect_artifact(Windows.EventLogs.Evtx)",
        ),
    ),

    # ── Behavioral rules (synthetic — generated in the watcher, no template) ──
    "Behavior.SpawnBurst": DetectorSpec(
        platform="behavior", synthetic=True, severity="high",
        signature_keys=(("entity",),),
        summary=lambda r: (
            f"Process spawn burst: {r.get('observed', '?')} spawns under parent "
            f"{r.get('entity', '?')} within {r.get('window_seconds', '?')}s "
            f"(≥{r.get('threshold', '?')})"
        ),
        pivots=(
            "velo.collect_artifact(Windows.System.Pslist)",
            "velo.collect_artifact(Linux.Sys.Pslist)",
        ),
    ),
    "Behavior.ConnFanout": DetectorSpec(
        platform="behavior", synthetic=True, severity="high",
        signature_keys=(("entity",),),
        summary=lambda r: (
            f"Connection fan-out: {r.get('observed', '?')} distinct remote IPs "
            f"from pid {r.get('entity', '?')} within {r.get('window_seconds', '?')}s "
            f"(≥{r.get('threshold', '?')})"
        ),
        pivots=(
            "velo.collect_artifact(Windows.Network.Netstat)",
            "velo.collect_artifact(Linux.Network.Netstat)",
            "enrich.abuseipdb_check",
        ),
    ),
    "Behavior.FirstSeenBinary": DetectorSpec(
        platform="behavior", synthetic=True, severity="medium",
        signature_keys=(("entity",),),
        summary=lambda r: (
            f"First-seen binary: {r.get('observed') or r.get('image_path', '?')} "
            f"(sha256 {str(r.get('entity', ''))[:12]}…)"
        ),
        pivots=(
            "enrich.vt_lookup_hash",
            "yara.scan_strings",
        ),
    ),
    "Behavior.RareParentChild": DetectorSpec(
        platform="behavior", synthetic=True, severity="high",
        signature_keys=(("entity",),),
        summary=lambda r: (
            f"Rare parent→child not in baseline: {r.get('entity', '?')}"
        ),
        pivots=(
            "velo.collect_artifact(Windows.System.Pslist)",
            "yara.scan_strings",
        ),
    ),
    "Behavior.DnsAnomaly": DetectorSpec(
        platform="behavior", synthetic=True, severity="high",
        signature_keys=(("entity",),),
        summary=lambda r: (
            f"DNS anomaly ({r.get('reason', '?')}): {r.get('entity', '?')}"
            + (f" (entropy {r.get('observed')})" if r.get('reason') == 'high_entropy'
               else f" ({r.get('observed')} queries)")
        ),
        pivots=(
            "enrich.vt_lookup_domain",
            "enrich.passive_dns",
        ),
    ),
    "Behavior.AuthBurst": DetectorSpec(
        platform="behavior", synthetic=True, severity="high",
        signature_keys=(("entity",),),
        summary=lambda r: (
            f"Auth-failure burst: {r.get('observed', '?')} failures from "
            f"{r.get('entity', '?')} within {r.get('window_seconds', '?')}s "
            f"(≥{r.get('threshold', '?')})"
        ),
        pivots=(
            "enrich.abuseipdb_check",
            "respond.suggest_containment",
        ),
    ),
}


# ── Baseline artifact sets per OS ────────────────────────────────────────────
#
# What monitor.baseline_capture collects to build the allowlist, branched by
# the client's OS. Persistence is captured separately via the snapshot artifact
# (see monitor.PERSISTENCE_SNAPSHOT_ARTIFACT) and is Linux-only for now.

BASELINE_ARTIFACTS_BY_OS: dict[str, list[str]] = {
    "linux": ["Linux.Sys.Pslist", "Linux.Network.Netstat"],
    "windows": ["Windows.System.Pslist", "Windows.Network.Netstat"],
}

# Bump when the baseline document shape OR the watched persistence surface
# changes, so start_watcher warns on baselines captured by an older Atlas (a
# stale baseline is missing allowlist entries for newly-watched paths and would
# false-positive on them). v3: added the Linux scheduled-task surface.
BASELINE_SCHEMA_VERSION = 3

_SUPPORTED_OS = ("linux", "windows")
_DEFAULT_OS = "linux"  # pre-registry behavior assumed Linux everywhere.


def normalize_os(value) -> str:
    """Map a Velociraptor OS string to our canonical 'linux'/'windows'.

    Tolerant of the shapes clients() returns across Velociraptor versions:
    a bare 'windows'/'linux', 'Windows'/'Linux', or None. Unknown → linux
    (the historical default), so an unrecognized OS never silently drops the
    whole detector set.
    """
    s = str(value or "").strip().lower()
    if s.startswith("win"):
        return "windows"
    if s.startswith("linux"):
        return "linux"
    return _DEFAULT_OS


def baseline_artifacts_for(os_name: str) -> list[str]:
    """Snapshot artifacts to collect for a client of the given OS."""
    return list(BASELINE_ARTIFACTS_BY_OS.get(normalize_os(os_name),
                                             BASELINE_ARTIFACTS_BY_OS[_DEFAULT_OS]))


# ── Lookup helpers (used by the watcher and monitor) ─────────────────────────

def known_detectors() -> list[str]:
    """Template-backed (pushable) detector artifact names, sorted.

    Excludes synthetic behavior rules, which have no Velociraptor template and
    are generated Python-side in the watcher.
    """
    return sorted(n for n, s in DETECTORS.items() if not s.synthetic)


def synthetic_detectors() -> list[str]:
    """Behavior-rule detector names (monitoring/behavior.py), sorted."""
    return sorted(n for n, s in DETECTORS.items() if s.synthetic)


def detectors_for_platform(os_name: str) -> list[str]:
    """Registered detector names targeting the given client OS, sorted."""
    target = normalize_os(os_name)
    return sorted(n for n, spec in DETECTORS.items() if spec.platform == target)


def platform_of(detector: str) -> Optional[str]:
    spec = DETECTORS.get(detector)
    return spec.platform if spec else None


def template_stem(detector: str) -> str:
    """Artifact template file stem for a detector (defaults to its name)."""
    spec = DETECTORS.get(detector)
    if spec and spec.template_stem:
        return spec.template_stem
    return detector


def row_signature(detector: str, row: dict) -> str:
    """Stable dedup key. "" means 'no signature — never dedup' (unknown detector)."""
    spec = DETECTORS.get(detector)
    if not spec:
        return ""
    parts = [str(_resolve(row, *group)) for group in spec.signature_keys]
    return "|".join(parts)


def summarize_row(detector: str, row: dict) -> str:
    """One-line human description for an alert's `summary` field."""
    spec = DETECTORS.get(detector)
    if not spec:
        return f"{detector}: " + json.dumps(row, default=str)[:160]
    return spec.summary(row)


def severity_of(detector: str) -> str:
    spec = DETECTORS.get(detector)
    return spec.severity if spec else "medium"


def pivots_for(detector: str) -> list[str]:
    spec = DETECTORS.get(detector)
    return list(spec.pivots) if spec else []
