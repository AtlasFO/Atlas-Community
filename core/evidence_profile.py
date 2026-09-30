"""Case evidence profile — factual inventory of artifact *classes* present.

This is intentionally NOT an investigation playbook. It answers only:
  - which evidence files exist under ``evidence/``
  - which artifact classes they belong to (disk, tabular, pcap, …)
  - which common classes are absent

Strategy, tool order, and which *compatible* tools to run remain LLM decisions.
Hard constraints (``tools.evidence_compat``) only refuse tools that need a
class the package does not contain.
"""
from __future__ import annotations

import json
import os
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "1.0"
PROFILE_NAME = "evidence_profile.json"

_LOCK = threading.RLock()

# Skip non-evidence noise under evidence/
try:
    from core.coverage_ledger import NOISE_DIR_NAMES as _SKIP_DIR_NAMES
except Exception:  # pragma: no cover
    _SKIP_DIR_NAMES = frozenset({
        ".git", "__pycache__", ".cache", "lost+found",
        "node_modules", "tools_temp_dir", ".venv", "venv",
        "site-packages",
    })
_SKIP_SUFFIXES = frozenset({".tmp", ".swp", ".lock", ".gitkeep"})
_SKIP_NAMES = frozenset({".gitkeep", "Thumbs.db", ".DS_Store"})

# Extension → primary class. Multiple extensions can share a class.
# Keep this a classifier, not a "what to do next" map.
_EXT_CLASS: dict[str, str] = {
    # Disk / volume images
    ".e01": "disk",
    ".ex01": "disk",
    ".s01": "disk",
    ".l01": "disk",
    ".aff": "disk",
    ".afd": "disk",
    ".afm": "disk",
    ".vmdk": "disk",
    ".vhd": "disk",
    ".vhdx": "disk",
    ".qcow": "disk",
    ".qcow2": "disk",
    ".dd": "disk",
    ".raw": "disk",
    ".img": "disk",
    ".iso": "disk",
    ".bin": "disk",  # often raw; gate still allows LLM to use non-disk tools on it
    # Memory
    ".vmem": "memory",
    ".mem": "memory",
    ".dmp": "memory",
    ".dump": "memory",
    ".lime": "memory",
    ".coredump": "memory",
    # Network
    ".pcap": "pcap",
    ".pcapng": "pcap",
    ".cap": "pcap",
    # Windows event logs (standalone)
    ".evtx": "windows_eventlog",
    ".evt": "windows_eventlog",
    # Tabular / SIEM-style exports
    ".csv": "tabular",
    ".tsv": "tabular",
    ".xlsx": "tabular",
    ".xls": "tabular",
    ".jsonl": "tabular",
    ".parquet": "tabular",
    # Mail
    ".eml": "email",
    ".msg": "email",
    ".pst": "email",
    ".ost": "email",
    ".mbox": "email",
}

# Classes we always mention as present/absent so the agent sees gaps clearly.
_TRACKED_CLASSES = (
    "disk",
    "memory",
    "pcap",
    "windows_eventlog",
    "tabular",
    "email",
    "file",
    "live",
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atlas_dir(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas"


def profile_path(case_dir: str | os.PathLike) -> Path:
    return atlas_dir(case_dir) / PROFILE_NAME


# Extensions that say nothing about structure. A firewall export, a Zeek
# log or an IIS log is a delimited table that happens to be called ".log";
# treating it as an opaque file refuses every table tool on it and keeps it
# out of coverage, so its rows are only ever grepped.
_SNIFF_SUFFIXES = frozenset({".log", ".txt", ".out", ".export", ".dat", ""})


def _looks_delimited(path: Path) -> bool:
    """One verdict shared with the table tools and the byte-scanner gate,
    so what the profile calls tabular is exactly what table.* accepts."""
    from core.input_kind import looks_delimited
    return looks_delimited(path)


# Packet-capture magic: pcap in both byte orders, microsecond and nanosecond
# variants, and the pcapng section header. A capture is recognised by these
# bytes, never by its name — exporters and sensors write captures as .log,
# .dump or .dat, and a name-only classifier then reports the pcap class
# absent from a case that is mostly packet data.
_PCAP_MAGICS = frozenset({
    b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",
    b"\x0a\x0d\x0d\x0a",
})


def _is_packet_capture(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) in _PCAP_MAGICS
    except OSError:
        return False


def classify_path(path: Path) -> str:
    """Return the primary artifact class for a single file path."""
    name = path.name
    if name in _SKIP_NAMES:
        return "file"
    lower = name.lower()
    # Multi-part E01: foo.E01, foo.E02, …
    if len(lower) > 4 and lower[-4] == "." and lower[-3] == "e" and lower[-2:].isdigit():
        return "disk"
    suf = path.suffix.lower()
    # Application DBs / dumps that reuse .raw/.bin (SRUM, EseDB, pagefile…).
    try:
        from core.artifact_kind import is_non_disk_container
        if is_non_disk_container(path):
            return "file"
    except Exception:
        pass
    # Ambiguous raw/bin extensions are often Windows/Defender noise inside
    # KAPE extracts — only treat as disk when the path looks like an image
    # intake (evidence root / images / ewf), not ProgramData/Defender Support.
    if suf in (".bin", ".raw", ".img"):
        parts = {p.casefold() for p in path.parts}
        noise = {
            "programdata", "program files", "program files (x86)",
            "windows defender", "defender", "wdav", "support",
            "winsxs", "system32", "syswow64",
        }
        if parts & noise:
            return "file"
        # Nested under a clearly-named image folder → disk
        imagey = {"images", "disk", "ewf", "dd", "forensic_images"}
        if parts & imagey or path.parent.name.lower().endswith(
            (".e01", ".ex01", ".vmdk", ".dd")
        ):
            return "disk"
        # Top-level under evidence/ (few path parts) → disk; deep tree → file
        try:
            # evidence/<name>.raw → disk; evidence/…/deep/foo.bin → file
            rel_parts = path.parts
            if "evidence" in [p.casefold() for p in rel_parts]:
                idx = [p.casefold() for p in rel_parts].index("evidence")
                depth = len(rel_parts) - idx - 1
                if depth <= 2:
                    return "disk"
            return "file"
        except Exception:
            return "file"
    if suf in _EXT_CLASS:
        return _EXT_CLASS[suf]
    # An ambiguous suffix says nothing about structure: judge the bytes.
    # Packet capture first — a capture is binary, so the delimited check
    # below could never claim it, but it would otherwise land as "file".
    if suf in _SNIFF_SUFFIXES and _is_packet_capture(path):
        return "pcap"
    # A structured export is tabular whatever it is called — judged by its
    # first two lines, never by a vendor's choice of extension.
    if suf in _SNIFF_SUFFIXES and suf != ".dat" and _looks_delimited(path):
        return "tabular"
    # Compound suffixes (.tar.gz) — fall through to generic file
    return "file"


def _iter_evidence_files(evidence_root: Path) -> Iterable[Path]:
    if not evidence_root.is_dir():
        return
    for root, dirs, files in os.walk(evidence_root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIR_NAMES and not d.startswith(".")]
        for fn in files:
            if fn in _SKIP_NAMES:
                continue
            p = Path(root) / fn
            if p.suffix.lower() in _SKIP_SUFFIXES:
                continue
            if not p.is_file():
                continue
            yield p


def _iter_derived_files(case: Path) -> Iterable[Path]:
    """Artifacts the run itself carved out, under ``analysis/`` and ``exports/``.

    On a disk-image case these are the only searchable sources that exist:
    ``evidence/`` holds a VMDK, and everything an analyst can actually query
    — EVTX, hives, parsed CSVs — is extracted from it during the run. Judging
    the case only by its intake tree told Atlas that ``tabular`` was absent
    while its own EvtxECmd CSVs sat in ``analysis/``, and the evidence-compat
    gate then refused ``table_*`` on them.
    """
    try:
        from core.evidence_catalog import iter_case_files, is_atlas_output
    except Exception:  # noqa: BLE001
        return
    for rel, abs_p in iter_case_files(case, ("analysis", "exports")):
        if is_atlas_output(rel):
            continue
        try:
            if abs_p.is_file() and abs_p.stat().st_size > 0:
                yield abs_p
        except OSError:
            continue


def live_hosts_configured() -> bool:
    """True when at least one live endpoint is registered for the operator."""
    try:
        from core.ssh import list_configured_hosts
        return bool(list_configured_hosts())
    except Exception:
        candidates = [
            Path.home() / "cases" / ".common" / "live_hosts.json",
            Path("/home/sansforensics/cases/.common/live_hosts.json"),
        ]
        for path in candidates:
            if not path.is_file():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict) and data.get("hosts"):
                return True
            if isinstance(data, list) and data:
                return True
        return False


def build_evidence_profile(case_dir: str | os.PathLike) -> dict[str, Any]:
    """Scan ``<case>/evidence/`` and return a fresh profile dict."""
    case = Path(case_dir).resolve()
    evidence_root = case / "evidence"
    counts: Counter[str] = Counter()
    samples: dict[str, list[str]] = {}
    files: list[dict[str, Any]] = []

    for path in _iter_evidence_files(evidence_root):
        cls = classify_path(path)
        counts[cls] += 1
        try:
            rel = str(path.relative_to(case))
        except ValueError:
            rel = str(path)
        files.append({"path": rel, "class": cls, "size": path.stat().st_size})
        bucket = samples.setdefault(cls, [])
        if len(bucket) < 5:
            bucket.append(rel)

    present = sorted(c for c, n in counts.items() if n > 0)
    if live_hosts_configured():
        present = sorted(set(present) | {"live"})
        counts["live"] = max(counts.get("live", 0), 1)

    # Derived artifacts extend what the case can *answer* without rewriting
    # what was handed to us: files/file_count/counts stay the intake
    # inventory (the staleness check compares file_count against the evidence
    # catalog, and high_value_tabular_index reads files), while
    # present_classes becomes the honest answer to "which tools apply here".
    derived_counts: Counter[str] = Counter()
    derived_samples: dict[str, list[str]] = {}
    for path in _iter_derived_files(case):
        cls = classify_path(path)
        derived_counts[cls] += 1
        try:
            rel = str(path.relative_to(case))
        except ValueError:
            rel = str(path)
        bucket = derived_samples.setdefault(cls, [])
        if len(bucket) < 5:
            bucket.append(rel)
    if derived_counts:
        present = sorted(set(present) | set(derived_counts))

    absent = [c for c in _TRACKED_CLASSES if c not in present]
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case.name,
        "updated_at": _utcnow(),
        "evidence_root": str(evidence_root),
        "file_count": len(files),
        "present_classes": present,
        "absent_classes": absent,
        "counts": dict(counts),
        "samples": samples,
        "files": files,
        "derived_counts": dict(derived_counts),
        "derived_samples": derived_samples,
        "derived_file_count": int(sum(derived_counts.values())),
        "notes": [
            "Profile is factual inventory only — not an investigation plan.",
            "Choose tools whose required evidence classes intersect present_classes.",
            "Tools needing only absent classes are refused by the evidence-compat gate.",
        ],
    }


def save_profile(case_dir: str | os.PathLike, profile: dict[str, Any]) -> Path:
    path = profile_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(profile)
    payload["updated_at"] = _utcnow()
    payload["schema_version"] = SCHEMA_VERSION
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    return path


def load_profile(case_dir: str | os.PathLike) -> dict[str, Any] | None:
    path = profile_path(case_dir)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def ensure_evidence_profile(
    case_dir: str | os.PathLike,
    *,
    refresh: bool = False,
) -> dict[str, Any]:
    """Load existing profile or build+persist one. Thread-safe.

    When ``refresh`` is False, still rebuild if the evidence catalog (or the
    evidence tree) is newer than the cached profile — closes the
    stale-profile class without requiring callers to remember refresh=True.
    """
    with _LOCK:
        if not refresh:
            existing = load_profile(case_dir)
            if (existing and existing.get("present_classes") is not None
                    and not _profile_is_stale(case_dir, existing)):
                return existing
        profile = build_evidence_profile(case_dir)
        try:
            save_profile(case_dir, profile)
        except OSError:
            pass
        return profile


def _profile_is_stale(
    case_dir: str | os.PathLike,
    profile: dict[str, Any],
) -> bool:
    """True when on-disk evidence likely drifted since the profile was saved."""
    root = Path(case_dir).resolve()
    ppath = profile_path(root)
    try:
        profile_mtime = ppath.stat().st_mtime if ppath.is_file() else 0.0
    except OSError:
        profile_mtime = 0.0

    # Catalog is updated by Plane A on evidence change — authoritative signal.
    cat = root / ".atlas" / "evidence_catalog.json"
    try:
        if cat.is_file() and cat.stat().st_mtime > profile_mtime + 0.01:
            return True
    except OSError:
        pass

    # Cheap tree signal: evidence/ directory mtime (updates on add/remove in
    # that directory; nested adds usually bump intermediate dirs on Linux).
    evidence = root / "evidence"
    try:
        if evidence.is_dir() and evidence.stat().st_mtime > profile_mtime + 0.01:
            return True
    except OSError:
        pass

    # Artifacts the run extracts land in analysis/ and exports/, never in
    # evidence/ — without this the profile stayed frozen at intake for the
    # whole run and kept reporting tabular/windows_eventlog as absent.
    for sub in ("analysis", "exports"):
        d = root / sub
        try:
            if d.is_dir() and d.stat().st_mtime > profile_mtime + 0.01:
                return True
        except OSError:
            pass

    # Catalog unit count vs profile file_count (when both present)
    try:
        from core.evidence_catalog import load_catalog
        units = len((load_catalog(root).get("units") or {}))
        cached = int(profile.get("file_count") or 0)
        if units and cached and units != cached:
            return True
    except Exception:
        pass
    return False


def present_class_set(profile: dict[str, Any] | None) -> frozenset[str]:
    if not profile:
        return frozenset()
    raw = profile.get("present_classes") or []
    return frozenset(str(c) for c in raw)


def format_profile_for_prompt(profile: dict[str, Any]) -> str:
    """Compact system-prompt block. Facts + soft guidance; no playbook steps."""
    present = profile.get("present_classes") or []
    absent = profile.get("absent_classes") or []
    counts = profile.get("counts") or {}
    samples = profile.get("samples") or {}
    lines = [
        "────────────────────────────────────────────────────────",
        "# EVIDENCE PROFILE (factual inventory — not a playbook)",
        "",
        "Built from `evidence/` plus what this run extracted into",
        "`analysis/` and `exports/`. Use it to avoid tools that need artifact",
        "classes this case does not contain. Strategy, tool order, and which",
        "*compatible* tools to run are still your decisions.",
        "",
        f"- files scanned: {profile.get('file_count', 0)}",
        f"- present classes: {', '.join(present) if present else '(none)'}",
        f"- absent classes: {', '.join(absent) if absent else '(none)'}",
        "",
        "Counts:",
    ]
    for cls in sorted(counts):
        lines.append(f"  - {cls}: {counts[cls]}")
    if samples:
        lines.append("")
        lines.append("Samples (up to 5 paths per class):")
        for cls in sorted(samples):
            for path in samples[cls]:
                lines.append(f"  - [{cls}] {path}")
    derived_counts = profile.get("derived_counts") or {}
    if derived_counts:
        lines += ["",
                  f"Extracted during this run ({profile.get('derived_file_count', 0)} "
                  "files under analysis/ and exports/ — queryable like any "
                  "other source, and counted in present classes):"]
        for cls in sorted(derived_counts):
            lines.append(f"  - {cls}: {derived_counts[cls]}")
        for cls in sorted(profile.get("derived_samples") or {}):
            for path in (profile["derived_samples"][cls])[:3]:
                lines.append(f"  - [{cls}] {path}")
    lines += [
        "",
        "Rules:",
        "- FIRST after start_execution_log: misc.inventory_evidence "
        "  (hard gate). It returns what exists, what is already parsed, "
        "  what still needs processing, and what to skip — follow "
        "  assessment.recommended_first_actions before any other evidence tool.",
        "- Prefer tools whose required classes intersect the present set.",
        "- Do not invent missing evidence (no EVTX parsing without event logs/",
        "  a disk image that could contain them; no EWF mount without a disk image;",
        "  no Volatility without memory; no PCAP tools without captures).",
        "- Prefer already-parsed exports (assessment.already_processed) with "
        "  table.* before re-running path parsers on raw sources.",
        "- When unsure of a basename, call misc.list_evidence_dir — do not guess",
        "  MFT.csv / USNJRNL.csv. Listing alone does not unlock the gate.",
        "- Loading an incompatible namespace still fails at the evidence-compat",
        "  gate — treat that as a signal to pick a different approach, not to retry.",
        "- Within the compatible set, investigate freely.",
    ]
    try:
        hv = high_value_tabular_index(profile, limit=12)
        if hv:
            lines += ["", "High-value parsed tabular (sample):"]
            for item in hv:
                lines.append(f"  - {item}")
    except Exception:
        pass
    return "\n".join(lines)


def high_value_tabular_index(
    profile: dict[str, Any],
    *,
    limit: int = 12,
) -> list[str]:
    """The tabular files most worth reading first: parser exports of the
    artifacts investigations rest on (named after the public tools that write
    them), files in a parser's output folder, and tables delivered at the top
    of the evidence tree, where a collection puts the exports it was asked
    for."""
    from core.path_hints import PARSER_DIR_RE

    files = profile.get("files") or []
    if not isinstance(files, list):
        return []
    # Artifact and parser names: universal, not any delivery's file names.
    tokens = (
        "mft", "usn", "usnjrnl", "evtx", "hayabusa", "chainsaw",
        "regripper", "amcache", "timeline",
    )
    scored: list[tuple[int, str]] = []
    for f in files:
        if not isinstance(f, dict):
            continue
        if f.get("class") not in ("tabular", "file"):
            continue
        rel = str(f.get("path") or "")
        low = rel.casefold().replace("\\", "/")
        if not low.endswith((".csv", ".tsv", ".txt")):
            continue
        score = 0
        if PARSER_DIR_RE.search(low):
            score += 20
        # A delimited table directly under evidence/ or one folder below it
        # (paths here are case-relative: evidence/x.csv, evidence/a/x.csv).
        # A README or a hash list is class "file", not "tabular".
        if f.get("class") == "tabular" and low.count("/") <= 2:
            score += 10
        for tok in tokens:
            if tok in low:
                score += 10
        if score:
            scored.append((score, rel))
    scored.sort(key=lambda x: (-x[0], x[1]))
    out: list[str] = []
    seen: set[str] = set()
    for _s, rel in scored:
        if rel in seen:
            continue
        seen.add(rel)
        out.append(rel)
        if len(out) >= limit:
            break
    return out
