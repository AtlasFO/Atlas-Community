"""Hayabusa: severity-scored Sigma detections over Windows event logs.

Hayabusa (github.com/Yamato-Security/hayabusa) runs its Sigma rule set over
.evtx files and writes one JSON object per detection: the rule title, its
level, the host, the time and the ATT&CK techniques the rule is tagged with.
install.sh unpacks the release pinned in install-versions.env into
~/.local/share/atlas/hayabusa. ATLAS_HAYABUSA_HOME names another folder with
the same layout (the executable beside its rules/ folder); a hayabusa on PATH
is the last resort. Scans use the dfir-timeline command of Hayabusa 4.
"""
from __future__ import annotations

import json
import os
import platform
import re
import subprocess
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from shutil import which as _which
from typing import Optional

from fastmcp import FastMCP

from core import run, output_safe, scale_timeout
from core.paths import assert_output_safe, unique_output_stem

mcp = FastMCP("hayabusa")

_DEFAULT_HOME = Path.home() / ".local" / "share" / "atlas" / "hayabusa"

# Rule levels, least severe first, and the short forms Hayabusa's JSON
# output uses for three of them.
_LEVELS = ("informational", "low", "medium", "high", "critical")
_SHORT_LEVELS = {"info": "informational", "med": "medium", "crit": "critical"}

# A rules folder with fewer rule files than this is a broken unpack, not a
# rule set, and a scan with it would report a clean log.
_MIN_RULE_FILES = 100

# The shape of an ATT&CK technique id (T1234, T1234.001), MITRE's public
# convention; tactic names and other tags in MitreTags do not match it.
_TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?")

# Hayabusa prints colour reset codes even with --no-color.
_COLOUR_CODE = re.compile(r"\x1b\[[0-9;]*m")

# Printed before a scan: the .evtx files found, and those kept once files
# that are unreadable or hold no channel a loaded rule reads are dropped.
_FOUND_RE = re.compile(r"Total event log files:\s*([\d,]+)")
_SCANNED_RE = re.compile(r"Evtx files loaded after channel filter:\s*([\d,]+)")

# A release names its executable hayabusa-<version>-lin-<cpu>-<libc>.
_RELEASE_NAME = re.compile(r"hayabusa-(\d+(?:\.\d+)*)-lin-([a-z0-9_]+?)-(musl|gnu)")
_CPU_NAMES = {"x86_64": "x64", "amd64": "x64", "aarch64": "aarch64", "arm64": "aarch64"}

_NOT_INSTALLED = (
    "Hayabusa is not installed: no executable in ATLAS_HAYABUSA_HOME or "
    "~/.local/share/atlas/hayabusa, and none on PATH. install.sh sets it up; "
    "by hand, unpack a release from "
    "https://github.com/Yamato-Security/hayabusa/releases into that folder "
    "so the executable sits beside its rules/ folder. hayabusa.status shows "
    "what is found."
)

_MITRE_HINT = (
    "Check the IDs under techniques with correlate.mitre_validate and pass "
    "the valid ones to misc.record_finding(mitre_techniques=[...]); "
    "correlate.killchain_timeline orders findings by them. To add techniques "
    "to a finding that is already recorded, record it again with "
    "supersedes=<its call id> so the new record replaces the old one. For "
    "detections without technique tags, run correlate.mitre_map on the rule "
    "title."
)


def _home() -> Optional[Path]:
    """The folder holding the executable and rules/: ATLAS_HAYABUSA_HOME when
    set, else the folder install.sh fills. None when it does not exist."""
    configured = os.environ.get("ATLAS_HAYABUSA_HOME", "").strip()
    home = Path(configured).expanduser() if configured else _DEFAULT_HOME
    return home if home.is_dir() else None


def _binary() -> Optional[Path]:
    """The executable for this machine. Among the release builds in the home
    folder for this CPU, the newest version wins, and of one version the
    statically linked musl build; a plain ``hayabusa`` there, then one on
    PATH, are the fallbacks."""
    home = _home()
    if home is not None:
        cpu = platform.machine().lower()
        cpu = _CPU_NAMES.get(cpu, cpu)
        builds = []
        for path in home.glob("hayabusa-*"):
            m = _RELEASE_NAME.fullmatch(path.name)
            if m and m.group(2) == cpu and path.is_file() and os.access(path, os.X_OK):
                version = tuple(int(part) for part in m.group(1).split("."))
                builds.append((version, m.group(3) == "musl", path))
        if builds:
            return max(builds)[2]
        plain = home / "hayabusa"
        if plain.is_file() and os.access(plain, os.X_OK):
            return plain
    on_path = _which("hayabusa")
    return Path(on_path) if on_path else None


def _rules() -> Optional[Path]:
    """The Sigma rules: rules/ in the home folder, else rules/ beside the
    executable, which is how a release unpacks."""
    home, exe = _home(), _binary()
    for folder in (home / "rules" if home else None,
                   exe.resolve().parent / "rules" if exe else None):
        if folder is not None and folder.is_dir():
            return folder
    return None


def _rule_files(rules: Optional[Path]) -> int:
    return sum(1 for _ in rules.rglob("*.yml")) if rules is not None else 0


def _has_scan_command(exe: Path) -> bool:
    """Whether this build has the scan command _cmd runs. A release that
    renames it (as Hayabusa 4 did) would otherwise fail every triage while
    looking installed."""
    try:
        proc = subprocess.run([str(exe), "dfir-timeline", "--help"],
                              capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def _plain(text: str) -> str:
    return _COLOUR_CODE.sub("", text or "")


def _level(raw) -> str:
    """The full name of a rule level (info -> informational); "" when raw is
    not one."""
    text = str(raw or "").strip().lower()
    return text if text in _LEVELS else _SHORT_LEVELS.get(text, "")


def _rank(level: str) -> int:
    return _LEVELS.index(level) if level in _LEVELS else 0


def _level_error(min_level: str) -> Optional[dict]:
    if _level(min_level):
        return None
    return {"success": False, "error": (
        f"min_level {min_level!r} is not a Hayabusa level; use one of "
        + ", ".join(_LEVELS))}


def _detections(jsonl_path: str) -> Iterator[dict]:
    """The rows of a Hayabusa JSONL file. Lines that do not parse are
    skipped: a scan cut short leaves a partial last line."""
    with open(jsonl_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                yield row


def _technique_ids(tags) -> list[str]:
    """The ATT&CK technique IDs among a detection's MitreTags, which come as
    a list or as one comma-separated string."""
    if isinstance(tags, str):
        tags = tags.split(",")
    ids = (str(tag).strip() for tag in tags or ())
    return [tag for tag in ids if _TECHNIQUE_ID.fullmatch(tag)]


def _tally(jsonl_path: str, min_level: str = "informational",
           top_n: int = 40) -> tuple[dict, int]:
    """The summary of the detections at or above min_level, tallied per rule
    with the totals, technique and host counts and time span derived from
    the tallies; and how many rows of the file are Hayabusa detections at
    all (a row with a RuleTitle), whatever their level."""
    floor = _rank(_level(min_level))
    tallies: dict[tuple, dict] = {}
    detections = 0
    rows = _detections(jsonl_path) if os.path.isfile(jsonl_path) else ()
    for row in rows:
        title = row.get("RuleTitle")
        if not title:
            continue
        detections += 1
        level = _level(row.get("Level")) or "unknown"
        if _rank(level) < floor:
            continue
        tally = tallies.setdefault((str(title), level), {
            "count": 0, "techniques": Counter(), "hosts": Counter(),
            "first": None, "last": None})
        tally["count"] += 1
        tally["techniques"].update(_technique_ids(row.get("MitreTags")))
        host = row.get("Computer")
        if isinstance(host, str) and host:
            tally["hosts"][host] += 1
        stamp = row.get("Timestamp")
        if isinstance(stamp, str) and stamp:
            tally["first"] = min(tally["first"] or stamp, stamp)
            tally["last"] = max(tally["last"] or stamp, stamp)

    levels, techniques, hosts = Counter(), Counter(), Counter()
    for (_title, level), tally in tallies.items():
        levels[level] += tally["count"]
        techniques.update(tally["techniques"])
        hosts.update(tally["hosts"])
    firsts = [t["first"] for t in tallies.values() if t["first"]]
    lasts = [t["last"] for t in tallies.values() if t["last"]]
    ranked = sorted(tallies.items(), reverse=True,
                    key=lambda item: (_rank(item[0][1]), item[1]["count"]))
    summary = {
        "detections": sum(levels.values()),
        "levels": dict(levels),
        "techniques": dict(techniques.most_common()),
        "hosts": dict(hosts.most_common(20)),
        "span": {"first": min(firsts, default=None),
                 "last": max(lasts, default=None)},
        "rules": [{
            "title": title, "level": level, "count": tally["count"],
            "techniques": sorted(tally["techniques"]),
            "hosts": sorted(tally["hosts"])[:5],
            "first": tally["first"], "last": tally["last"],
        } for (title, level), tally in ranked[:top_n]],
        "min_level": _level(min_level) or "informational",
    }
    return summary, detections


def _evtx_files(console: str) -> Optional[dict]:
    """How many .evtx files the scan found and how many it read."""
    found, scanned = _FOUND_RE.search(console), _SCANNED_RE.search(console)
    if not (found and scanned):
        return None
    return {"found": int(found.group(1).replace(",", "")),
            "scanned": int(scanned.group(1).replace(",", ""))}


def _cmd(evtx_path: str, output_path: str, min_level: str = "informational",
         profile: str = "super-verbose") -> list[str]:
    """The argv of one scan. The background job in tools/jobs.py builds its
    command with this function too, so both run the same scan."""
    exe, rules = _binary(), _rules()
    if exe is None or rules is None:
        raise RuntimeError(_NOT_INSTALLED)
    source = "--directory" if os.path.isdir(evtx_path) else "--file"
    return [
        str(exe), "dfir-timeline", source, evtx_path,
        "--rules", str(rules),
        "--min-level", _level(min_level) or min_level,
        "--profile", profile,           # super-verbose carries MitreTags
        "--output", output_path,
        "--output-type", "jsonl",
        "--iso-8601",                   # UTC timestamps that sort as text
        "--no-wizard",                  # load every rule, ask nothing
        "--clobber",                    # a rerun replaces its own output
        "--quiet", "--quiet-errors", "--no-color", "--no-summary",
    ]


@mcp.tool()
def status() -> dict:
    """Whether Hayabusa is ready to scan: the executable, the rules folder,
    its rule count, whether the build has the scan command Atlas runs, and
    anything wrong with them. Call it when a hayabusa.* tool fails."""
    problems = []
    configured = os.environ.get("ATLAS_HAYABUSA_HOME", "").strip()
    if configured and _home() is None:
        problems.append(f"ATLAS_HAYABUSA_HOME is set to {configured}, which is not a folder")
    exe, rules = _binary(), _rules()
    if exe is None:
        return {"success": True, "installed": False, "error": _NOT_INSTALLED,
                "problems": problems}
    found = _rule_files(rules)
    if rules is None:
        problems.append("no rules/ folder in the home folder or beside the executable")
    elif found < _MIN_RULE_FILES:
        problems.append(f"only {found} rule files in {rules}: unpack the release again")
    if not _has_scan_command(exe):
        problems.append(f"{exe.name} has no dfir-timeline command: Atlas runs the "
                        "Hayabusa 4 command line (install-versions.env pins the release)")
    return {"success": True, "installed": True, "binary": str(exe),
            "rules": str(rules) if rules else None, "rule_count": found,
            "healthy": not problems, "problems": problems}


@mcp.tool()
@output_safe
def triage(evtx_path: str, output_dir: str,
           min_level: str = "informational",
           profile: str = "super-verbose",
           top_n: int = 40) -> dict:
    """Run Hayabusa's Sigma rules over Windows event logs and get the
    detections back ranked by severity, each with the ATT&CK techniques of
    the rule that fired: a fast, attack-shaped first look at .evtx evidence.

    evtx_path: one .evtx file, or a folder that is searched recursively.
    output_dir: folder for the full JSONL of detections, under analysis/,
                exports/ or reports/, never inside the evidence tree.
    min_level: lowest rule level to load: informational, low, medium, high
               or critical.
    profile: Hayabusa output profile. Keep super-verbose unless you have a
             reason: a profile without MitreTags leaves techniques empty, and
             the timesketch profiles rename the fields this summary reads.
    top_n: how many rules the rules list holds.

    Returns detections, levels, techniques, hosts, span and the rules that
    fired (most severe first), evtx_files (found vs scanned; a warning names
    files that were not scanned, about which zero detections says nothing),
    and output_path of the full JSONL. Next: check the technique IDs with
    correlate.mitre_validate before misc.record_finding; cut the same output
    again with hayabusa.summary.
    """
    exe, rules = _binary(), _rules()
    if exe is None:
        return {"success": False, "error": _NOT_INSTALLED}
    found = _rule_files(rules)
    if found < _MIN_RULE_FILES:
        return {"success": False, "error": (
            f"Hayabusa's rules folder holds {found} rule files, too few for a "
            "rule set: unpack the release again. hayabusa.status shows the "
            "paths.")}
    refused = _level_error(min_level)
    if refused:
        return refused
    if not os.path.exists(evtx_path):
        return {"success": False, "error": f"evtx_path not found: {evtx_path}"}

    assert_output_safe(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"hayabusa_{unique_output_stem(evtx_path)}.jsonl")
    result = run(_cmd(evtx_path, output_path, min_level, profile),
                 timeout=scale_timeout(1800, evtx_path), output_dir=output_dir,
                 stdout_filter=_plain)
    # Hayabusa names a fatal problem (no .evtx found, unreadable input) on an
    # [ERROR] line, which it writes to stderr.
    console = _plain(f"{result.get('stdout') or ''}\n{result.get('stderr') or ''}")
    errors = [line.strip() for line in console.splitlines() if "[ERROR]" in line]
    produced = os.path.isfile(output_path)
    if result.get("success") and errors and not produced:
        result["success"] = False
    if not result.get("success"):
        if errors:
            result.setdefault("error", "Hayabusa: " + "; ".join(errors[:3]))
        return result
    summary, _ = _tally(output_path, min_level, top_n)
    result.update(summary)
    files = _evtx_files(console)
    if files:
        result["evtx_files"] = files
        missed = files["found"] - files["scanned"]
        if missed > 0:
            result["warning"] = (
                f"{missed} of {files['found']} .evtx files were not scanned: "
                "unreadable, or no loaded rule reads their channel. Zero "
                "detections says nothing about them.")
    result["output_path"] = output_path if produced else None
    result["hint"] = _MITRE_HINT
    return result


@mcp.tool()
def summary(jsonl_path: str, min_level: str = "low", top_n: int = 40) -> dict:
    """Summarise a JSONL that hayabusa.triage or its background job wrote,
    without scanning again: raise min_level to cut noise, or top_n to list
    more rules. Reads only that file."""
    if not os.path.isfile(jsonl_path):
        return {"success": False, "error": f"Not a file: {jsonl_path}"}
    refused = _level_error(min_level)
    if refused:
        return refused
    result, detections = _tally(jsonl_path, min_level, top_n)
    if not detections and os.path.getsize(jsonl_path) > 0:
        return {"success": False, "error": (
            f"{jsonl_path} holds no Hayabusa detections (no row has a "
            "RuleTitle); it is not hayabusa.triage output.")}
    result.update(success=True, jsonl_path=jsonl_path, hint=_MITRE_HINT)
    return result
