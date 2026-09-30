"""Curate master timeline to investigation-relevant events only.

``reports/master_timeline.tsv`` is a **curated** deliverable, not a raw dump.
Live capture may accumulate thousands of EVTX/session rows under
``.timeline_build/``; finalize collapses repetitive chains, then this module:

  1. Infers asserted evidence classes from the case narrative (claims/findings)
  2. Scores each event by narrative binding (not a hardcoded type deny-list)
  3. Keeps multi-perspective producers for asserted classes
  4. Aggregates auth/process storms into summary rows with user lists

Everything else stays in the raw builder store for search — it does not ship
in ``master_timeline.tsv``.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from plugins.timeline_builder.aggregate import aggregate_storms
from plugins.timeline_builder.models import NormalizedTimelineEvent
from plugins.timeline_builder.taxonomy import (
    AGGREGATABLE_EVENT_TYPES,
    CORROBORATIVE_EVENT_TYPES,
    VOLUME_EVENT_TYPES,
    EvidenceClass,
    classes_from_narrative,
    classify_event,
    narrative_texts_from_case,
)

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_MAC_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b"
)
_HOST_RE = re.compile(
    r"\b(?:TS|PC|WS|SRV|DC)[A-Za-z0-9_-]{2,}\b"
    r"|\b[A-Za-z0-9_-]+\.(?:corp|local|internal)[A-Za-z0-9_.-]*\b",
    re.IGNORECASE,
)
_DOMAIN_USER_RE = re.compile(
    r"\b([A-Za-z0-9_.-]+)\\([A-Za-z][A-Za-z0-9_.-]{1,31})\b"
)
_CAMEL_USER_RE = re.compile(
    r"\b([A-Z][a-z]{2,}[A-Z][A-Za-z0-9]{1,20})\b"
)
_SERIAL_RE = re.compile(r"\b([A-Fa-f0-9]{8,16})\b")
_FQDN_RE = re.compile(r"^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$")
_ACCOUNT_DIGIT_RE = re.compile(
    r"\b([A-Za-z][A-Za-z0-9_.-]{0,12}\d[A-Za-z0-9_.-]{0,12})\b"
)

# Generic English / OS tokens — not case-specific hostnames.
_TOKEN_BLOCKLIST = frozenset({
    "failed", "failing", "windows", "security", "administrator", "system",
    "local service", "network service", "dictionaryattacklockreset",
    "cachedisk", "secevent", "tpm2", "tss2-esys",
})


def _norm_token(tok: str) -> str:
    t = (tok or "").strip().lower()
    if "\\" in t:
        t = t.split("\\")[-1]
    if t.endswith("$"):
        t = t[:-1]
    for suf in (".zip", ".txt", ".log", ".csv", ".evtx", ".xlsx"):
        if t.endswith(suf):
            t = t[: -len(suf)]
    return t


def _accept_token(tok: str) -> bool:
    t = _norm_token(tok)
    if len(t) < 3 or t in _TOKEN_BLOCKLIST:
        return False
    if t.isdigit():
        return False
    if "_" in t and any(x in t for x in ("log", "session", "conn", "export", "diag")):
        return False
    if t.count("-") >= 2 and not _looks_like_host(t) and ":" not in t:
        if not re.match(r"^(ts|pc|ws|srv|dc)", t):
            return False
    return True


def _looks_like_host(tok: str) -> bool:
    t = _norm_token(tok)
    if not t:
        return False
    if _FQDN_RE.match(t):
        return True
    if _HOST_RE.fullmatch(t) or _HOST_RE.match(t):
        return True
    if re.match(r"^(ts|pc|ws|srv|dc)", t):
        return True
    # Generic hostnames: letters+digits (HOST01, webserver2) — not users
    if re.match(r"^[a-z]{2,}\d{2,}$", t):
        return True
    return False


def _looks_like_ip(tok: str) -> bool:
    return bool(_IP_RE.fullmatch(tok or ""))


def _looks_like_mac(tok: str) -> bool:
    return bool(_MAC_RE.fullmatch(tok or ""))


def _looks_like_serial(tok: str) -> bool:
    t = (tok or "").lower()
    return bool(_SERIAL_RE.fullmatch(t)) and not t.isdigit()


def _is_computer_account(user: str) -> bool:
    return (user or "").strip().endswith("$")


def focus_tokens_from_claims(case_dir: str | Path) -> set[str]:
    hosts, principals = focus_sets_from_claims(case_dir)
    return hosts | principals


def focus_sets_from_claims(case_dir: str | Path) -> tuple[set[str], set[str]]:
    """Return (host_tokens, principal_tokens) from active claims."""
    case_dir = Path(case_dir)
    path = case_dir / ".atlas" / "claim_graph.json"
    if not path.is_file():
        return set(), set()
    try:
        import json
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set(), set()

    hosts: set[str] = set()
    principals: set[str] = set()
    nodes = data.get("nodes") or {}
    for node in nodes.values() if isinstance(nodes, dict) else nodes:
        if not isinstance(node, dict):
            continue
        if (node.get("kind") or "claim") != "claim":
            continue
        if (node.get("status") or "").lower() == "superseded":
            continue

        host = _norm_token(str(node.get("host") or ""))
        if _accept_token(host):
            if _looks_like_host(host):
                hosts.add(host)
            else:
                principals.add(host)

        evidence_bits = []
        for ev in node.get("evidence") or []:
            if isinstance(ev, dict):
                evidence_bits.append(str(ev.get("locator") or ""))
                evidence_bits.append(str(ev.get("artifact") or ""))

        blob = " ".join([
            str(node.get("statement") or ""),
            str(node.get("reasoning") or ""),
            str(node.get("temporal_qualifier") or ""),
            *evidence_bits,
        ])

        for ip in _IP_RE.findall(blob):
            if _accept_token(ip):
                principals.add(ip.lower())
        for mac in _MAC_RE.findall(blob):
            principals.add(mac.lower().replace("-", ":"))
        for m in _HOST_RE.findall(blob):
            n = _norm_token(m)
            if not _accept_token(n):
                continue
            if "_" in n:
                prefix = n.split("_", 1)[0]
                if _looks_like_host(prefix) and _accept_token(prefix):
                    hosts.add(prefix)
                continue
            hosts.add(n)
        for _dom, user in _DOMAIN_USER_RE.findall(blob):
            if user.endswith("$"):
                n = _norm_token(user)
                if _accept_token(n):
                    hosts.add(n)
                continue
            n = _norm_token(user)
            if _accept_token(n) and len(n) <= 32:
                principals.add(n)
        for user in _ACCOUNT_DIGIT_RE.findall(blob):
            n = _norm_token(user)
            if (
                _accept_token(n)
                and 3 <= len(n) <= 16
                and "/" not in user
                and "." not in n
                and not _looks_like_host(n)
                and not re.search(r"[a-z][A-Z]|[A-Z]{2,}.*\d|\$", user)
            ):
                principals.add(n)
        for user in _CAMEL_USER_RE.findall(blob):
            n = _norm_token(user)
            if _accept_token(n) and len(n) <= 32 and not _looks_like_host(n):
                principals.add(n)
        for serial in _SERIAL_RE.findall(blob):
            n = serial.lower()
            if _accept_token(n) and re.fullmatch(r"[a-f0-9]{8,16}", n):
                principals.add(n)

    return hosts, principals


def _event_blob(ev: NormalizedTimelineEvent) -> str:
    return " ".join([
        ev.host or "",
        ev.user or "",
        ev.title or "",
        ev.description or "",
        ev.record_ref or "",
    ]).lower()


def _token_in_text(tok: str, text: str) -> bool:
    if not tok or not text:
        return False
    return bool(
        re.search(rf"(?<![a-z0-9_.-]){re.escape(tok)}(?![a-z0-9_.-])", text)
    )


def _matches_principals(ev: NormalizedTimelineEvent, principals: set[str]) -> bool:
    if not principals:
        return False
    user_n = _norm_token(ev.user)
    if user_n and user_n in principals and not _is_computer_account(ev.user or ""):
        return True
    blob = _event_blob(ev)
    for tok in principals:
        if _token_in_text(tok, blob):
            return True
    return False


def _matches_hosts(ev: NormalizedTimelineEvent, hosts: set[str]) -> bool:
    if not hosts:
        return False
    host_n = _norm_token(ev.host)
    if host_n and (
        host_n in hosts
        or any(host_n == h or host_n.startswith(h + ".") for h in hosts)
    ):
        return True
    user_n = _norm_token(ev.user)
    if _is_computer_account(ev.user or "") and user_n in hosts:
        return True
    blob = _event_blob(ev)
    for tok in hosts:
        if _token_in_text(tok, blob):
            return True
    return False


def _is_narrative_anchor(ev: NormalizedTimelineEvent) -> bool:
    et = ev.event_type or ""
    title = (ev.title or "").lower()
    if et == "investigation_finding" or title.startswith("finding "):
        return True
    if (ev.facts or {}).get("claim_id"):
        return True
    return False


def score_event(
    ev: NormalizedTimelineEvent,
    *,
    hosts: set[str],
    principals: set[str],
    asserted: set[EvidenceClass],
    focus: set[str],
) -> int:
    """Per-event relevance score (0 = drop). Higher = keep preferentially."""
    if _is_narrative_anchor(ev):
        return 100

    et = ev.event_type or ""
    title = (ev.title or "").lower()
    cls, producer = classify_event(
        et,
        source_identifier=ev.source_identifier or "",
        source_artifact=ev.source_artifact or "",
        title=ev.title or "",
    )
    principal_hit = _matches_principals(ev, principals)
    host_hit = _matches_hosts(ev, hosts)
    class_asserted = cls in asserted or (
        cls == EvidenceClass.MALWARE_EXECUTION and EvidenceClass.EXECUTION in asserted
    )

    is_chain = (
        et == "event_chain_summary"
        or "more events in this eventchain" in title
    )
    if is_chain:
        if not focus:
            return 40
        return 75 if principal_hit else 0

    if principal_hit:
        return 85

    if not focus:
        # Pre-claim orientation: keep corroborative + auth samples, not bulk process/file
        if et in CORROBORATIVE_EVENT_TYPES:
            return 60
        if et in {
            "successful_logon", "failed_logon", "network_logon",
            "explicit_credential_logon",
        } or "logged on" in title or "credential" in title:
            return 55
        if et in VOLUME_EVENT_TYPES:
            return 0
        return 30

    # Focus exists — host alone is not enough for volume types
    if host_hit and class_asserted:
        if et in VOLUME_EVENT_TYPES and not principal_hit:
            # Volume + asserted class on focus host: keep as corroboration
            # but only for non-SYSTEM / non-empty meaningful users, OR
            # corroborative producers, OR aggregated summaries.
            if (ev.facts or {}).get("aggregated"):
                return 70
            user_n = _norm_token(ev.user)
            if user_n and user_n not in {"system", "local service", "network service"}:
                return 65
            if et in {
                "failed_logon", "successful_logon", "network_logon",
                "explicit_credential_logon",
            }:
                return 50  # auth on focus host still matters for coverage
            return 0  # SYSTEM process/file noise on focus host
        return 70

    if host_hit and et in CORROBORATIVE_EVENT_TYPES:
        return 68

    if host_hit and cls == EvidenceClass.USB_DEVICE:
        return 72

    return 0


def curate_relevant_events(
    events: Iterable[NormalizedTimelineEvent],
    *,
    case_dir: str | Path | None = None,
    focus_tokens: set[str] | None = None,
    focus_hosts: set[str] | None = None,
    focus_principals: set[str] | None = None,
    asserted_classes: set[EvidenceClass] | None = None,
    enabled: bool = True,
    max_unmatched_noise: int = 0,
    aggregate: bool = True,
    aggregate_min_group: int = 8,
    aggregate_bucket_seconds: int = 600,
) -> tuple[list[NormalizedTimelineEvent], dict]:
    """Filter collapsed events down to investigation-relevant rows."""
    ordered = list(events)
    if not enabled:
        return ordered, {
            "enabled": False,
            "input_events": len(ordered),
            "output_events": len(ordered),
            "dropped": 0,
            "mode": "passthrough",
        }

    hosts = set(focus_hosts or ())
    principals = set(focus_principals or ())
    if case_dir is not None and not hosts and not principals and not focus_tokens:
        hosts, principals = focus_sets_from_claims(case_dir)
    elif focus_tokens and not hosts and not principals:
        for t in focus_tokens:
            n = _norm_token(t)
            if _looks_like_ip(n) or _looks_like_mac(n) or _looks_like_serial(n):
                principals.add(n)
            elif _looks_like_host(n):
                hosts.add(n)
            else:
                principals.add(n)

    focus = hosts | principals

    if asserted_classes is None:
        texts: list[str] = []
        if case_dir is not None:
            texts = narrative_texts_from_case(case_dir)
        if not texts:
            # Fall back to event titles already seeded from findings
            texts = [
                f"{e.title} {e.description}"
                for e in ordered
                if _is_narrative_anchor(e)
            ]
        asserted = classes_from_narrative(texts)
    else:
        asserted = set(asserted_classes)

    # Aggregate storms first so summaries can score as coverage units
    agg_stats: dict = {"enabled": False}
    working = ordered
    if aggregate:
        working, agg_stats = aggregate_storms(
            ordered,
            min_group_size=aggregate_min_group,
            bucket_seconds=aggregate_bucket_seconds,
            aggregatable_types=AGGREGATABLE_EVENT_TYPES,
        )
        agg_stats["enabled"] = True

    kept: list[NormalizedTimelineEvent] = []
    dropped = 0
    unmatched_noise = 0
    scores_kept: list[int] = []
    producers_kept: set[str] = set()

    for ev in working:
        sc = score_event(
            ev, hosts=hosts, principals=principals,
            asserted=asserted, focus=focus,
        )
        if sc > 0:
            kept.append(ev)
            scores_kept.append(sc)
            _cls, prod = classify_event(
                ev.event_type or "",
                source_identifier=ev.source_identifier or "",
                source_artifact=ev.source_artifact or "",
                title=ev.title or "",
            )
            producers_kept.add(prod)
            continue

        if not focus and unmatched_noise < max_unmatched_noise:
            kept.append(ev)
            unmatched_noise += 1
            continue
        dropped += 1

    # Coverage pass: for each asserted class, if we have *any* events of that
    # class on a focus host in the working set but kept none, promote the
    # highest-signal samples (principal- Prefer, else first chronologically).
    kept_ids = {id(e) for e in kept}
    by_class_host: dict[tuple[EvidenceClass, str], list[NormalizedTimelineEvent]] = {}
    for ev in working:
        cls, _prod = classify_event(
            ev.event_type or "",
            source_identifier=ev.source_identifier or "",
            source_artifact=ev.source_artifact or "",
            title=ev.title or "",
        )
        if cls not in asserted:
            continue
        if not _matches_hosts(ev, hosts) and focus:
            continue
        key = (cls, _norm_token(ev.host) or "*")
        by_class_host.setdefault(key, []).append(ev)

    coverage_promoted = 0
    for cls in asserted:
        already = any(
            classify_event(
                e.event_type or "",
                source_identifier=e.source_identifier or "",
                source_artifact=e.source_artifact or "",
                title=e.title or "",
            )[0] == cls
            for e in kept
        )
        if already:
            continue
        candidates: list[NormalizedTimelineEvent] = []
        for (c, _h), evs in by_class_host.items():
            if c == cls:
                candidates.extend(evs)
        if not candidates:
            continue
        # Prefer principal hits, then aggregated, then earliest
        candidates.sort(
            key=lambda e: (
                0 if _matches_principals(e, principals) else 1,
                0 if (e.facts or {}).get("aggregated") else 1,
                e.timestamp or "",
            )
        )
        for ev in candidates[:3]:
            if id(ev) in kept_ids:
                continue
            kept.append(ev)
            kept_ids.add(id(ev))
            coverage_promoted += 1
            dropped = max(0, dropped - 1)

    kept.sort(key=lambda e: (e.timestamp or "", e.host or "", e.event_type or ""))
    stats = {
        "enabled": True,
        "mode": "narrative_score",
        "input_events": len(ordered),
        "output_events": len(kept),
        "dropped": dropped,
        "focus_token_count": len(focus),
        "focus_hosts_sample": sorted(hosts)[:15],
        "focus_principals_sample": sorted(principals)[:15],
        "focus_tokens_sample": sorted(focus)[:20],
        "asserted_classes": sorted(c.value for c in asserted),
        "producers_kept": sorted(producers_kept)[:40],
        "coverage_promoted": coverage_promoted,
        "aggregate": agg_stats,
        "score_min_kept": min(scores_kept) if scores_kept else 0,
        "score_max_kept": max(scores_kept) if scores_kept else 0,
    }
    return kept, stats
