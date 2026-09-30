"""Deterministic cross-source evidence reconciliation.

Compares normalized forensic events extracted from multiple evidence sources
(Wazuh JSON, EVTX CSV, Hayabusa CSV, investigation timelines) and surfaces
coverage gaps, earliest-event mismatches, and claim conflicts.

Used by correlate.cross_source_reconciliation and reason.pre_report_check.
"""
from __future__ import annotations

import csv
import json
import itertools
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator

_MANIFEST_PATH = Path(__file__).with_name("reconciliation_manifest.yaml")

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PRIVATE_IP_RE = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)"
)
_LOGON_TYPE_RE = re.compile(r"Logon Type:\s*(\d+)", re.IGNORECASE)
_EID_COLS = ("EventId", "Event ID", "EventID", "event_id", "eventID")
_TS_COLS = ("TimeCreated", "Timestamp", "timestamp", "timecreated", "Date")
_HOST_COLS = ("Computer", "computer", "Hostname", "host", "Machine")
_USER_COLS = ("UserName", "User", "user", "TargetUserName", "SubjectUserName")
_IP_COLS = ("IpAddress", "ipAddress", "src_ip", "Source Network Address", "SourceIp")


@dataclass
class NormalizedEvent:
    profile: str
    timestamp: str
    host: str
    user: str
    event_id: str
    logon_type: str
    src_ip: str
    auth_package: str
    source_kind: str
    source_path: str
    source_label: str
    record_ref: str
    extras: dict[str, Any] = field(default_factory=dict)

    def match_key(self) -> tuple:
        return (
            self.event_id,
            self.src_ip,
            self.host,
            self.timestamp[:16],  # minute bucket
            self.logon_type,
        )


@dataclass
class Discrepancy:
    kind: str
    profile: str
    severity: str  # info | warning | blocking
    message: str
    details: dict[str, Any] = field(default_factory=dict)


def _load_manifest() -> dict:
    try:
        import yaml
        raw = yaml.safe_load(_MANIFEST_PATH.read_text(encoding="utf-8")) or {}
    except Exception:
        raw = {}
    return raw


def _pick(row: dict, names: tuple[str, ...]) -> str:
    for n in names:
        if n in row and row[n] not in (None, ""):
            return str(row[n]).strip()
    lower = {k.lower(): v for k, v in row.items()}
    for n in names:
        v = lower.get(n.lower())
        if v not in (None, ""):
            return str(v).strip()
    return ""


def _normalize_ts(raw: str) -> str:
    if not raw:
        return ""
    s = str(raw).replace("T", " ").split("+")[0].split("Z")[0]
    return s.split(".")[0].strip()


def _external_ips(text: str) -> list[str]:
    out: list[str] = []
    for ip in _IPV4_RE.findall(text or ""):
        if not _PRIVATE_IP_RE.match(ip):
            out.append(ip)
    return out


def _is_external_ip(ip: str) -> bool:
    return bool(ip and not _PRIVATE_IP_RE.match(ip))


def _logon_type_from_text(text: str) -> str:
    m = _LOGON_TYPE_RE.search(text or "")
    return m.group(1) if m else ""


def _source_label(kind: str) -> str:
    return {
        "wazuh_json": "Wazuh alert export",
        "evtx_csv": "Windows Security event log CSV",
        "hayabusa_csv": "Windows event log CSV",
        "timeline_tsv": "Investigation timeline",
    }.get(kind, kind)


def discover_sources(case_dir: Path) -> list[dict]:
    """Find reconcilable artifacts under case evidence/ and analysis/."""
    case_dir = Path(case_dir)
    found: list[dict] = []

    from core.evidence_catalog import iter_output_files
    for base in (case_dir / "evidence", case_dir / "analysis"):
        if not base.is_dir():
            continue
        for p in iter_output_files(base, prune_mounts=base.name != "evidence"):
            if not p.is_file():
                continue
            kind = _classify_source(p)
            if kind:
                found.append({
                    "kind": kind,
                    "path": str(p),
                    "label": _source_label(kind),
                })
    return found


def _classify_source(path: Path) -> str | None:
    name = path.name.lower()
    parent = str(path).lower()
    if path.suffix == ".json" and "wazuh" in parent:
        return "wazuh_json"
    if path.suffix == ".csv":
        if "hayabusa" in name or "evtx" in name or "security" in name:
            return _csv_kind(path)
        if "mft" in name or "registry" in name or "prefetch" in name:
            return None
        return _csv_kind(path)
    if path.suffix == ".tsv" and ("timeline" in name or "master_timeline" in name):
        return "timeline_tsv"
    return None


def _csv_kind(path: Path) -> str | None:
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            fields = set(reader.fieldnames or [])
    except OSError:
        return None
    if not fields:
        return None
    has_eid = any(c in fields for c in _EID_COLS)
    has_ts = any(c in fields for c in _TS_COLS)
    if has_eid and has_ts:
        if "hayabusa" in path.name.lower():
            return "hayabusa_csv"
        return "evtx_csv"
    return None


def _iter_wazuh_records(path: Path, *, limit: int = 0) -> Iterator[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return
    records = data.get("records")
    if not isinstance(records, list):
        return
    it = (rec for rec in records if isinstance(rec, dict))
    if limit > 0:
        it = itertools.islice(it, limit)
    yield from it


def _wazuh_to_event(rec: dict, profile: str, eids: set[int], path: Path) -> NormalizedEvent | None:
    eid_raw = str(rec.get("event_id") or rec.get("eventID") or "")
    try:
        eid = int(eid_raw)
    except ValueError:
        return None
    if eid not in eids:
        return None
    ts = _normalize_ts(str(rec.get("timestamp") or ""))
    src_ip = str(rec.get("src_ip") or rec.get("ipAddress") or "").strip()
    user = str(rec.get("user") or "").strip()
    host = str(rec.get("computer") or rec.get("host") or "").strip()
    logon_type = ""
    auth_package = ""
    record_ref = ""
    full_log = rec.get("full_log") or ""
    if isinstance(full_log, str):
        logon_type = _logon_type_from_text(full_log)
        if "Authentication Package:" in full_log:
            m = re.search(r"Authentication Package:\s*(\S+)", full_log)
            if m:
                auth_package = m.group(1)
        try:
            fl = json.loads(full_log) if full_log.startswith("{") else None
            if isinstance(fl, dict):
                win = fl.get("win", {})
                sys = win.get("system", {}) if isinstance(win, dict) else {}
                host = host or str(sys.get("computer") or "")
                record_ref = str(sys.get("eventRecordID") or "")
        except json.JSONDecodeError:
            m = re.search(r"eventRecordID[\"']?\s*[:=]\s*[\"']?(\d+)", full_log)
            if m:
                record_ref = m.group(1)
        if not src_ip:
            src_ip = _external_ips(full_log)[0] if _external_ips(full_log) else ""
    return NormalizedEvent(
        profile=profile,
        timestamp=ts,
        host=host,
        user=user,
        event_id=str(eid),
        logon_type=logon_type,
        src_ip=src_ip,
        auth_package=auth_package,
        source_kind="wazuh_json",
        source_path=str(path),
        source_label=_source_label("wazuh_json"),
        record_ref=record_ref or f"{path.name}:{ts}:{eid}:{src_ip}",
        extras={
            "rule_id": rec.get("rule_id"),
            "rule_description": rec.get("rule_description"),
        },
    )


def _csv_to_events(path: Path, profile: str, eids: set[int], kind: str) -> list[NormalizedEvent]:
    out: list[NormalizedEvent] = []
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for i, row in enumerate(reader, 1):
                eid_raw = _pick(row, _EID_COLS)
                try:
                    eid = int(eid_raw)
                except ValueError:
                    continue
                if eid not in eids:
                    continue
                ts = _normalize_ts(_pick(row, _TS_COLS))
                if not ts:
                    continue
                ip = _pick(row, _IP_COLS)
                if not ip:
                    blob = " ".join(str(v) for v in row.values())
                    ips = _external_ips(blob)
                    ip = ips[0] if ips else ""
                logon_type = _pick(row, ("Logon Type", "LogonType", "logon_type"))
                if not logon_type:
                    logon_type = _logon_type_from_text(
                        _pick(row, ("MapDescription", "Details", "Description"))
                    )
                out.append(NormalizedEvent(
                    profile=profile,
                    timestamp=ts,
                    host=_pick(row, _HOST_COLS),
                    user=_pick(row, _USER_COLS),
                    event_id=str(eid),
                    logon_type=logon_type,
                    src_ip=ip,
                    auth_package=_pick(row, ("Authentication Package", "AuthPackage")),
                    source_kind=kind,
                    source_path=str(path),
                    source_label=_source_label(kind),
                    record_ref=f"{path.name}:{i}:{eid}",
                ))
    except OSError:
        pass
    return out


def _timeline_to_events(path: Path, profile: str, eids: set[int]) -> list[NormalizedEvent]:
    out: list[NormalizedEvent] = []
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh, delimiter="\t")
            for i, row in enumerate(reader, 1):
                desc = " ".join(str(v) for v in row.values())
                eid = ""
                for token in ("4688", "4624", "4625", "5156"):
                    if f" {token}" in desc or f"({token}" in desc or f"ID {token}" in desc:
                        if int(token) in eids:
                            eid = token
                            break
                if not eid:
                    if profile == "successful_logon" and re.search(
                        r"(?i)logon|logged on|explicit logon|rdp", desc
                    ):
                        eid = "4624"
                    else:
                        continue
                ts = _normalize_ts(
                    _pick(row, ("Timestamp", "timestamp", "Time", "time"))
                )
                if not ts:
                    continue
                ips = _external_ips(desc)
                out.append(NormalizedEvent(
                    profile=profile,
                    timestamp=ts,
                    host=_pick(row, ("Machine", "Host", "Computer")),
                    user=_pick(row, ("User", "Account")),
                    event_id=eid,
                    logon_type=_logon_type_from_text(desc),
                    src_ip=ips[0] if ips else "",
                    auth_package="",
                    source_kind="timeline_tsv",
                    source_path=str(path),
                    source_label=_source_label("timeline_tsv"),
                    record_ref=f"{path.name}:{i}",
                    extras={"description": desc[:300]},
                ))
    except OSError:
        pass
    return out


def extract_events(
    sources: list[dict],
    profile_name: str,
    event_ids: list[int],
    *,
    focus_ips: list[str] | None = None,
    max_per_source: int = 5000,
) -> list[NormalizedEvent]:
    eids = set(int(x) for x in event_ids)
    focus = {ip.strip() for ip in (focus_ips or []) if ip.strip()}
    events: list[NormalizedEvent] = []

    for src in sources:
        path = Path(src["path"])
        kind = src["kind"]
        batch: list[NormalizedEvent] = []
        if kind == "wazuh_json":
            # Prefer attacker-IP bundles; cap parse volume on large exports.
            cap = 5000 if "attacker" in path.name.lower() else 2000
            for rec in _iter_wazuh_records(path, limit=cap):
                ev = _wazuh_to_event(rec, profile_name, eids, path)
                if ev:
                    batch.append(ev)
        elif kind in ("evtx_csv", "hayabusa_csv"):
            batch = _csv_to_events(path, profile_name, eids, kind)
        elif kind == "timeline_tsv":
            batch = _timeline_to_events(path, profile_name, eids)

        if focus:
            batch = [e for e in batch if e.src_ip in focus or not e.src_ip]
        events.extend(batch[:max_per_source])
    return events


def _family(kind: str, manifest: dict) -> str:
    families = manifest.get("source_families") or {}
    for fam, kinds in families.items():
        if kind in kinds:
            return fam
    if kind == "wazuh_json":
        return "siem"
    if kind in ("evtx_csv", "hayabusa_csv"):
        return "disk"
    if kind == "timeline_tsv":
        return "timeline"
    return "other"


def _earliest_by_ip(events: list[NormalizedEvent]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for ev in sorted(events, key=lambda e: e.timestamp):
        if not ev.src_ip or not _is_external_ip(ev.src_ip):
            continue
        if ev.src_ip not in out:
            out[ev.src_ip] = {
                "timestamp": ev.timestamp,
                "host": ev.host,
                "user": ev.user,
                "logon_type": ev.logon_type,
                "source_kind": ev.source_kind,
                "source_path": ev.source_path,
                "record_ref": ev.record_ref,
            }
    return out


def _earliest_by_ip_and_family(events: list[NormalizedEvent], manifest: dict) -> dict[str, dict[str, dict]]:
    out: dict[str, dict[str, dict]] = {}
    for ev in sorted(events, key=lambda e: e.timestamp):
        if not ev.src_ip or not _is_external_ip(ev.src_ip):
            continue
        fam = _family(ev.source_kind, manifest)
        out.setdefault(ev.src_ip, {})
        if fam not in out[ev.src_ip]:
            out[ev.src_ip][fam] = {
                "timestamp": ev.timestamp,
                "logon_type": ev.logon_type,
                "source_kind": ev.source_kind,
                "source_path": ev.source_path,
            }
    return out


def _find_discrepancies(
    profile: str,
    events: list[NormalizedEvent],
    manifest: dict,
) -> list[Discrepancy]:
    discrepancies: list[Discrepancy] = []
    by_family: dict[str, list[NormalizedEvent]] = {}
    for ev in events:
        by_family.setdefault(_family(ev.source_kind, manifest), []).append(ev)

    per_ip_family = _earliest_by_ip_and_family(events, manifest)
    for ip, families in per_ip_family.items():
        siem = families.get("siem")
        disk = families.get("disk")
        timeline = families.get("timeline")
        if siem and timeline and siem["timestamp"] < timeline["timestamp"]:
            discrepancies.append(Discrepancy(
                kind="earliest_mismatch",
                profile=profile,
                severity="blocking",
                message=(
                    f"Earliest {profile} from {ip} in SIEM ({siem['timestamp']}) "
                    f"predates timeline ({timeline['timestamp']})"
                ),
                details={
                    "src_ip": ip,
                    "siem_earliest": siem,
                    "timeline_earliest": timeline,
                    "disk_earliest": disk,
                },
            ))
        if siem and not disk:
            # SIEM has events but disk CSV has none for this IP
            siem_count = sum(1 for e in events if e.src_ip == ip and _family(e.source_kind, manifest) == "siem")
            if siem_count:
                discrepancies.append(Discrepancy(
                    kind="siem_only",
                    profile=profile,
                    severity="warning",
                    message=(
                        f"{profile} events from {ip} appear in SIEM but not in "
                        "disk event-log CSV exports (possible log rotation/retention gap)"
                    ),
                    details={"src_ip": ip, "siem_earliest": siem},
                ))

    # Unmatched high-value SIEM successes
    if profile == "successful_logon" and "siem" in by_family and "timeline" in by_family:
        siem_keys = {e.match_key() for e in by_family["siem"]}
        timeline_keys = {e.match_key() for e in by_family["timeline"]}
        for ev in by_family["siem"]:
            if ev.src_ip and _is_external_ip(ev.src_ip) and ev.match_key() not in timeline_keys:
                discrepancies.append(Discrepancy(
                    kind="not_in_timeline",
                    profile=profile,
                    severity="warning",
                    message=(
                        f"Successful logon from {ev.src_ip} at {ev.timestamp} "
                        f"in SIEM is absent from investigation timeline"
                    ),
                    details={
                        "src_ip": ev.src_ip,
                        "timestamp": ev.timestamp,
                        "logon_type": ev.logon_type,
                        "record_ref": ev.record_ref,
                    },
                ))
    return discrepancies


def detect_focus_ips(case_dir: Path, sources: list[dict]) -> list[str]:
    """Infer external IPs worth reconciling from Wazuh bundle metadata first."""
    ips: set[str] = set()
    attacker_paths: list[Path] = []
    for src in sources:
        if src["kind"] != "wazuh_json":
            continue
        p = Path(src["path"])
        attacker_paths.append(p)
        try:
            # Read only the first 8 KB — description + start of records is enough
            # for IP discovery without parsing multi-MB exports.
            head = p.read_text(encoding="utf-8", errors="replace")[:8192]
        except OSError:
            continue
        m = re.search(r"attacker IPs\s*\[([^\]]+)\]", head, re.IGNORECASE)
        if m:
            for ip in _IPV4_RE.findall(m.group(1)):
                if _is_external_ip(ip):
                    ips.add(ip)
        for ip in _IPV4_RE.findall(head):
            if _is_external_ip(ip):
                ips.add(ip)
    # If metadata did not yield IPs, sample first records only (not full file).
    if not ips:
        for p in attacker_paths[:5]:
            for rec in itertools.islice(_iter_wazuh_records(p), 200):
                for key in ("src_ip", "ipAddress"):
                    ip = str(rec.get(key) or "").strip()
                    if _is_external_ip(ip):
                        ips.add(ip)
    return sorted(ips)


def _prioritize_sources(sources: list[dict], focus_ips: list[str] | None) -> list[dict]:
    """Reduce Wazuh parse volume — prefer attacker/auth bundles over full dumps."""
    non_wazuh = [s for s in sources if s["kind"] != "wazuh_json"]
    wazuh = [s for s in sources if s["kind"] == "wazuh_json"]
    if not wazuh:
        return sources

    preferred: list[dict] = []
    secondary: list[dict] = []
    for s in wazuh:
        p = s["path"].lower()
        if any(k in p for k in ("attacker", "auth_events", "lateral_movement")):
            preferred.append(s)
        elif "all_alerts" in p or "high_severity" in p:
            secondary.append(s)
        else:
            secondary.append(s)

    chosen = preferred or secondary[:3]
    if focus_ips and preferred:
        chosen = preferred
    elif len(chosen) > 4:
        chosen = chosen[:4]
    return non_wazuh + chosen


def run_reconciliation(
    case_dir: str | Path,
    *,
    profiles: list[str] | None = None,
    focus_ips: list[str] | None = None,
    write_outputs: bool = True,
) -> dict:
    """Run cross-source reconciliation for a case directory."""
    case_dir = Path(case_dir)
    manifest = _load_manifest()
    profile_defs: dict = manifest.get("profiles") or {}
    if not profile_defs:
        profile_defs = {
            "successful_logon": {"event_ids": [4624], "description": "EID 4624"},
        }

    names = profiles or list(profile_defs.keys())
    sources = discover_sources(case_dir)
    if not sources:
        return {
            "success": True,
            "note": "no reconcilable sources found",
            "sources_scanned": [],
            "profiles": {},
        }

    if not focus_ips:
        focus_ips = detect_focus_ips(case_dir, sources)

    sources = _prioritize_sources(sources, focus_ips)

    results: dict[str, Any] = {}
    all_blocking: list[str] = []

    for pname in names:
        pdef = profile_defs.get(pname) or {}
        eids = pdef.get("event_ids") or []
        events = extract_events(sources, pname, eids, focus_ips=focus_ips)
        by_source: dict[str, int] = {}
        for ev in events:
            key = f"{ev.source_kind}:{Path(ev.source_path).name}"
            by_source[key] = by_source.get(key, 0) + 1

        discrepancies = _find_discrepancies(pname, events, manifest)
        blocking = [d.message for d in discrepancies if d.severity == "blocking"]
        all_blocking.extend(blocking)

        results[pname] = {
            "description": pdef.get("description", ""),
            "event_count": len(events),
            "by_source": by_source,
            "focus_ips": focus_ips,
            "earliest_by_src_ip": _earliest_by_ip(events),
            "earliest_by_src_ip_and_family": _earliest_by_ip_and_family(events, manifest),
            "events_sample": [asdict(e) for e in events[:50]],
            "discrepancies": [asdict(d) for d in discrepancies],
            "blocking_issues": blocking,
        }

    summary = {
        "success": True,
        "case_dir": str(case_dir),
        "sources_scanned": sources,
        "profiles_run": names,
        "focus_ips": focus_ips,
        "profiles": results,
        "blocking_issues": all_blocking,
        "ready_for_report": len(all_blocking) == 0,
    }

    if write_outputs:
        analysis = case_dir / "analysis"
        analysis.mkdir(parents=True, exist_ok=True)
        json_path = analysis / "cross_source_reconciliation.json"
        json_path.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False, default=str) + "\n",
            encoding="utf-8",
        )
        md_path = analysis / "cross_source_reconciliation.md"
        md_path.write_text(_render_markdown(summary), encoding="utf-8")
        summary["json_path"] = str(json_path)
        summary["markdown_path"] = str(md_path)

    return summary


def _render_markdown(summary: dict) -> str:
    lines = [
        "# Cross-Source Reconciliation",
        "",
        f"**Case:** `{summary.get('case_dir', '')}`",
        f"**Profiles:** {', '.join(summary.get('profiles_run') or [])}",
        f"**Focus IPs:** {', '.join(summary.get('focus_ips') or []) or '(all external)'}",
        "",
    ]
    if summary.get("blocking_issues"):
        lines.append("## Blocking issues")
        for issue in summary["blocking_issues"]:
            lines.append(f"- {issue}")
        lines.append("")

    for pname, pdata in (summary.get("profiles") or {}).items():
        lines.append(f"## {pname}")
        lines.append(pdata.get("description", ""))
        lines.append("")
        lines.append("| Source | Events |")
        lines.append("|---|---:|")
        for src, n in sorted((pdata.get("by_source") or {}).items()):
            lines.append(f"| {src} | {n} |")
        lines.append("")
        earliest = pdata.get("earliest_by_src_ip") or {}
        if earliest:
            lines.append("### Earliest per external IP")
            lines.append("| IP | Timestamp | Logon type | Source |")
            lines.append("|---|---|---|---|")
            for ip, row in sorted(earliest.items()):
                lines.append(
                    f"| {ip} | {row.get('timestamp','')} | "
                    f"{row.get('logon_type','')} | {row.get('source_kind','')} |"
                )
            lines.append("")
        for disc in pdata.get("discrepancies") or []:
            lines.append(f"- **{disc.get('severity','').upper()}** [{disc.get('kind')}]: {disc.get('message')}")
        lines.append("")
    return "\n".join(lines)


def load_reconciliation_result(case_dir: str | Path) -> dict | None:
    path = Path(case_dir) / "analysis" / "cross_source_reconciliation.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def case_needs_reconciliation(case_dir: str | Path) -> bool:
    """True when SIEM exports exist alongside disk/timeline sources."""
    sources = discover_sources(case_dir)
    kinds = {s["kind"] for s in sources}
    has_siem = "wazuh_json" in kinds
    has_other = bool(kinds & {"evtx_csv", "hayabusa_csv", "timeline_tsv"})
    return has_siem and has_other


def findings_trigger_reconciliation(findings: list[dict], manifest: dict | None = None) -> bool:
    manifest = manifest or _load_manifest()
    patterns: list[re.Pattern] = []
    for pdef in (manifest.get("profiles") or {}).values():
        for pat in pdef.get("claim_patterns") or []:
            try:
                patterns.append(re.compile(pat))
            except re.error:
                continue
    if not patterns:
        patterns = [
            re.compile(r"(?i)initial access"),
            re.compile(r"(?i)first (?:successful )?(?:logon|authentication|access)"),
        ]
    for f in findings:
        if (f.get("confidence") or "").upper() not in ("CONFIRMED", "LIKELY"):
            continue
        text = str(f.get("description") or "")
        if any(p.search(text) for p in patterns):
            return True
    return False
