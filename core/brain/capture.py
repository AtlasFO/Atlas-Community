"""Staged memory capture from finished agent runs.

Called from ``atlas train`` (with the in-memory review) and from
``atlas brain capture --case DIR`` (reads reports/<CASE_ID>_run_review.md).
Writes ONLY brain/logs/runs/ and brain/inbox/memory-candidates/ — durable
memory changes require human review via ``atlas brain approve``.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from core.brain import answer_key, frontmatter, gt_exposure, secrets, store

MAX_CANDIDATES_PER_RUN = 8

# evaluate_challenged self-corrections collapse to ≤1 aggregate candidate,
# staged only when a run hits this many (below it they are protocol noise).
CHALLENGED_AGGREGATE_MIN = 3

# IOC-ish tokens: quoting raw evidence marks a candidate sensitive.
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HASH = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
# Credential assignment (password=, the Java EE form-login field j_password:,
# api_key=…). A candidate can carry a credential in a form secrets.redact
# does not know — flag it sensitive so it goes confidential.
_CRED = re.compile(
    r"(?i)\b(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|j_password)\b"
    r"\s*[=:]\s*\S")

# Candidate types that are durable by construction — never hard-dropped on a
# case-specific signal alone (a technique/issue can legitimately cite an IP or
# hostname). Only run-residue types (workflow, action tool_gotcha) are dropped.
_DROPPABLE_TYPES = frozenset({"workflow", "tool_gotcha"})


def _is_run_residue(candidate_type: str, text: str) -> bool:
    """True for a droppable-type candidate whose text/title is case-specific
    run residue (imperative run-action or case-identifier signals). Reuses the
    existing _review_hints detector — no new heuristics. Most of a night's
    candidates can be this shape; staging them drowns the brain."""
    if candidate_type not in _DROPPABLE_TYPES:
        return False
    return _review_hints(text)["likely_case_specific"]


class CaptureError(Exception):
    pass


# ── review / trace mining ────────────────────────────────────────────────

def _recommendation_bullets(review_text: str) -> list[str]:
    """Bullets under a 'Recommendations' heading (any level). LLM output is
    free-form: no heading means no candidates, never a crash."""
    bullets: list[str] = []
    in_section = False
    for line in review_text.splitlines():
        heading = re.match(r"#+\s*(.+)", line)
        if heading:
            in_section = "recommendation" in heading.group(1).lower()
            continue
        if in_section:
            m = re.match(r"\s*(?:[-*]|\d+\.)\s+(.+)", line)
            if m:
                bullets.append(m.group(1).strip())
            elif bullets and re.match(r"\s{2,}\S", line):
                bullets[-1] += " " + line.strip()  # wrapped bullet
    return bullets


def _load_trace(case_dir: Path, case_id: str) -> dict:
    for pattern in (f"analysis/{case_id}_trace.json", "analysis/*_trace.json"):
        for p in sorted(case_dir.glob(pattern)):
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
    return {}


def _trace_digest(trace: dict) -> dict:
    entries = trace.get("entries") or []
    tiers = Counter(str(e.get("confidence", "")).upper()
                    for e in entries if e.get("type") == "finding")
    corrections = [
        {"trigger": str(e.get("trigger", "")),
         "prior": str(e.get("prior_belief", "")),
         "new": str(e.get("new_belief", ""))}
        for e in entries if e.get("type") == "self_correction"
    ]
    from core.execution_log import is_trace_opened
    errors = sum(1 for e in entries if e.get("type") == "system_error" and not is_trace_opened(e))
    return {"tiers": dict(tiers), "self_corrections": corrections,
            "system_errors": errors, "entry_count": len(entries)}


def _injection_manifest(case_dir: Path) -> dict | None:
    """Brain-injection manifest written by agent.prompts._brain_context at
    prompt-build time. Absent when the run predates injection logging or ran
    with ATLAS_NO_BRAIN — the summary says so rather than guessing."""
    path = case_dir / "analysis" / "brain_injection.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _injection_lines(injection: dict | None) -> str:
    if not injection:
        return ("- (no injection manifest — run predates injection logging "
                "or brain injection was disabled)")
    lines: list[str] = []
    mem = injection.get("memory") or {}
    if mem.get("files"):
        trunc = " — TRUNCATED at cap" if mem.get("truncated") else ""
        lines.append(f"- durable memory: {', '.join(mem['files'])} "
                     f"({mem.get('bytes', '?')}/{mem.get('cap', '?')} B{trunc})")
    for c in injection.get("concepts") or []:
        pin = ", pinned" if c.get("pinned") else ""
        lines.append(f"- concept `{c.get('path') or c.get('title')}`: "
                     f"{c.get('status', '?')}{pin}")
    ret = injection.get("retrieval") or {}
    if ret.get("tags"):
        lines.append(f"- retrieval tags: {', '.join(ret['tags'])}")
    for note in ret.get("notes") or []:
        lines.append(f"- note `{note.get('path') or note.get('title')}`: "
                     f"{note.get('status', '?')}")
    for ex in injection.get("excluded_same_case") or []:
        lines.append(f"- excluded (same-case): "
                     f"`{ex.get('path') or ex.get('title')}` "
                     f"(origin {ex.get('origin_case_id', '?')})")
    if mem.get("same_case_mentions"):
        lines.append("- durable memory: dropped line(s) naming the active "
                     "case (same-case guard, Tier A line-level)")
    if not lines:
        lines.append("- (brain enabled, nothing injected)")
    if injection.get("generated_at"):
        lines.append(f"- manifest generated: {injection['generated_at']}")
    return "\n".join(lines)


def _accuracy(case_dir: Path) -> dict | None:
    """Best-effort per-case accuracy when the case ships a ground truth.
    Only meaningful in-process right after a run (the execution log
    singleton still holds the findings)."""
    # Every known GT location, not just evidence/ (root-level copies were
    # silently missed and accuracy_trend never staged).
    gt = answer_key._find_ground_truth(case_dir)
    if gt is None:
        return None
    try:
        from tools.accuracy import accuracy_compare
        fn = getattr(accuracy_compare, "fn", accuracy_compare)
        result = fn(str(gt))
        if isinstance(result, dict):
            if result.get("unscorable"):
                return {"unscorable": True}
            summary = result.get("summary") or {}
            return {k: summary[k] for k in ("precision", "recall", "f1")
                    if k in summary}
    except Exception:
        pass
    return None


# ── junk pre-filter ──────────────────────────────────────────────────────
# Heuristic signals that a candidate is a case-specific to-do rather than a
# durable lesson. Recorded as decision support for the review panel — never
# used to suppress staging. Kept conservative: a genuine tool gotcha that
# says "re-run with a narrower pattern" must not be flagged, so individually
# ambiguous cues (weak signals) only flag when two distinct ones co-occur.

_WEEKDAY = r"(?:mon|tues|wednes|thurs|fri|satur|sun)day"

# One match from any strong category ⇒ likely_case_specific.
_STRONG_SIGNALS: dict[str, list[re.Pattern]] = {
    "deadline": [
        re.compile(r"\bdeadline\b", re.I),
        re.compile(r"\b(?:is|are|was)\s+due\b", re.I),
        re.compile(rf"\bdue\s+(?:by\s+|on\s+)?(?:{_WEEKDAY}|today|tomorrow"
                   r"|next\s+week|end\s+of\s+(?:day|week))\b", re.I),
        re.compile(rf"\bby\s+(?:{_WEEKDAY}|end\s+of\s+(?:day|week)|eod|eow)\b",
                   re.I),
    ],
    "next_run_todo": [
        re.compile(r"\bnext\s+run\b", re.I),
        re.compile(r"\bfollow\s+up\b", re.I),
        re.compile(r"\b(?:confirm|check|verify|clarify|coordinate|ask)\s+with"
                   r"\s+the\s+(?:operator|analyst|examiner|client|customer"
                   r"|team)\b", re.I),
        re.compile(r"\bask\s+the\s+(?:operator|analyst|examiner|client"
                   r"|customer|team)\b", re.I),
    ],
    "case_logistics": [
        re.compile(r"\bevidence\s+locker\b", re.I),
        re.compile(r"\be01\s+(?:is|was)\s+in\b|\be01\s+arriv\w+\b"
                   r"|\bnew\s+e01\b", re.I),
    ],
}

# Weak signals also occur in genuine lessons; two distinct categories must
# co-occur to flag. C: is excluded — every Windows lesson mentions it.
_WEAK_SIGNALS: dict[str, list[re.Pattern]] = {
    "rerun_recheck": [re.compile(r"\bre-?(?:run|check|scan|examine)\b", re.I)],
    "specific_host": [re.compile(r"\b(?:WIN|DESKTOP|LAPTOP)-[A-Z0-9]{2,}\b")],
    "drive_letter": [
        re.compile(r"\b[a-bd-z]:\s?(?:partition|drive|volume)\b", re.I),
    ],
}

# Leading verbs typical of to-do fragments ("Get the report out") rather
# than noun-phrase lessons ("Volatility needs …"). Counts as a weak signal.
_IMPERATIVE_VERBS = frozenset((
    "run", "check", "confirm", "verify", "follow", "ask", "schedule",
    "email", "send", "get", "pull", "finish", "complete", "submit",
    "upload", "deliver", "remember", "review", "update",
))


def _match_signals(text: str, table: dict[str, list[re.Pattern]]) -> list[str]:
    hits = []
    for name, patterns in table.items():
        for pattern in patterns:
            m = pattern.search(text)
            if m:
                hits.append(f"{name}: {m.group(0)}")
                break
    return hits


def _review_hints(text: str) -> dict:
    """Score candidate text for junk signals. Decision support only —
    the review panel still judges every candidate."""
    strong = _match_signals(text, _STRONG_SIGNALS)
    weak = _match_signals(text, _WEAK_SIGNALS)
    first = re.match(r"[\s#>*`-]*([A-Za-z][\w-]*)", text)
    if first and first.group(1).lower() in _IMPERATIVE_VERBS:
        weak.append(f"imperative_title: {first.group(1)}")
    return {"likely_case_specific": bool(strong) or len(weak) >= 2,
            "signals": strong + weak}


# ── candidate staging ────────────────────────────────────────────────────

def _existing_hashes(root: Path) -> set[str]:
    hashes = set()
    for d in ("inbox/memory-candidates", "inbox/processed"):
        for p in (root / d).glob("*.md"):
            meta, _, _ = frontmatter.parse(p.read_text(encoding="utf-8",
                                                       errors="replace"))
            h = meta.get("content_hash")
            if h:
                hashes.add(str(h))
    return hashes


def _content_hash(text: str) -> str:
    normalized = re.sub(r"\W+", " ", text.lower()).strip()
    return hashlib.sha1(normalized.encode()).hexdigest()[:16]


def _is_sensitive(text: str, redacted: bool) -> bool:
    if redacted:
        return True
    if "evidence/" in text:
        return True
    if _CRED.search(text):
        return True
    return len(_IPV4.findall(text)) + len(_HASH.findall(text)) > 2


def _stage_candidate(root: Path, case_id: str, candidate_type: str,
                     text: str, why: str, destination: str,
                     existing: set[str], date: str, timestamp: str,
                     run_id: str, command: str,
                     ak_secrets: list[str], *,
                     title: str | None = None,
                     confidence: str = "medium",
                     knowledge_kind: str = "",
                     why_reusable: str = "",
                     supporting_evidence: str = "",
                     origin_sources: list[str] | None = None,
                     learning_phase: str = "capture",
                     source_description: str | None = None) -> Path | None:
    clean, findings = secrets.redact(text)
    # Answer-key leak guard: scrub any verbatim ground-truth secret the
    # analyst recovered, so the pending candidate never holds the raw answer,
    # and flag it so `atlas brain approve` refuses to promote it.
    clean, ak_hits = answer_key.redact(clean, ak_secrets)
    contains_answer_key = bool(ak_hits)
    h = _content_hash(clean)
    if h in existing:
        return None
    existing.add(h)
    sensitive = _is_sensitive(clean, bool(findings)) or contains_answer_key
    display_title = (title or clean).strip()
    if len(display_title) > 70:
        display_title = display_title[:67] + "…"
    tags = ["agent-run", candidate_type.replace("_", "-")]
    if knowledge_kind:
        tags.append(knowledge_kind.replace("_", "-"))
    if learning_phase and learning_phase != "capture":
        tags.append(learning_phase.replace("_", "-"))
    sources = [str(s) for s in (origin_sources or []) if str(s).strip()]
    meta = {
        "title": display_title,
        "type": "memory_candidate",
        "created": timestamp, "updated": timestamp,
        "status": "pending_review",
        "source_classification": "confidential" if sensitive else "internal",
        "confidence": confidence or "medium",
        "candidate_type": candidate_type,
        "knowledge_kind": knowledge_kind or "",
        "suggested_destination": destination,
        "content_hash": h,
        "review_hints": _review_hints(clean),
        "tags": tags,
        "related": [],
        "source": {"type": "agent_run", "url": "",
                   "description": (source_description
                                   or f"Staged from {case_id} run")},
        "origin": {"case_id": case_id, "run_id": run_id, "command": command,
                   "learning_phase": learning_phase,
                   "sources": sources},
        "explainability": {
            "why_exists": why,
            "why_reusable": why_reusable,
            "supporting_evidence": supporting_evidence,
            "origin_sources": sources,
            "suggested_destination": destination,
        },
        "risk": {"contains_sensitive_data": sensitive,
                 "contains_answer_key": contains_answer_key,
                 "requires_user_approval": True},
        "entities": {"cases": [case_id], "tools": [], "techniques": [],
                     "actors": [], "cves": []},
    }
    why_reusable_s = why_reusable.strip() or (
        "Reusable across investigations if the lesson is generalized "
        "(no case IOCs or customer-specific facts).")
    evidence_s = supporting_evidence.strip() or "(see origin sources)"
    sources_s = ", ".join(f"`{s}`" for s in sources) if sources else "(capture)"
    kind_line = (f"\n**Knowledge kind:** `{knowledge_kind}`\n"
                 if knowledge_kind else "")
    body = (f"# Candidate Memory\n\n"
            f"## Proposed Entry\n\n{clean}\n\n"
            f"## Why This Candidate Exists\n\n{why}\n\n"
            f"## Why This May Be Useful\n\n{why}\n\n"
            f"## Why Reusable\n\n{why_reusable_s}\n\n"
            f"## Supporting Evidence\n\n{evidence_s}\n\n"
            f"## Origin Sources\n\n{sources_s}\n\n"
            f"## Source Context\n\nCase `{case_id}` "
            f"(learning phase: `{learning_phase}`)."
            f"{kind_line}\n\n"
            f"## Suggested Destination\n\n`{destination}`\n\n"
            f"## Suggested Action\n\n- approve / edit / reject\n")
    slug = store.slugify(display_title or clean)[:48]
    dest = (root / "inbox/memory-candidates" /
            f"{date}-{store.slugify(case_id)}-{candidate_type}-{slug}-{h[:6]}.md")
    dest.write_text(frontmatter.serialize(meta, body), encoding="utf-8")
    return dest


def _classify_recommendation(text: str) -> tuple[str, str]:
    lower = text.lower()
    if any(w in lower for w in ("tool", "volatility", "plaso", "flag",
                                "command", "parser")):
        return "tool_gotcha", "wiki/tools"
    if any(w in lower for w in ("mitre", "ttp", "technique", "artifact")):
        return "technique_insight", "wiki/techniques"
    return "workflow", "wiki/concepts"


# ── run summary ──────────────────────────────────────────────────────────

def _exposure_lines(exposure: dict | None) -> str:
    """Seen-vs-reported rollup for the run summary. Ids only for non-reported
    items — descriptions stay in analysis/gt_exposure.json (and secret values
    are redacted even there)."""
    if not exposure:
        return "- (no ground truth or no trace — exposure not audited)"
    counts = exposure.get("summary") or {}
    order = ("reported", "surfaced-not-reported", "never-surfaced",
             "unassessable")
    lines = ["- " + " · ".join(f"{k}: {counts.get(k, 0)}" for k in order)]
    for it in exposure.get("items", []):
        if it["classification"] in ("surfaced-not-reported", "never-surfaced"):
            seen = (f" (first seen call #{it['first_seen_call_id']}, "
                    f"{it['first_seen_tool']})"
                    if it.get("first_seen_call_id") is not None else "")
            lines.append(f"- {it['classification']}: `{it['id']}`{seen}")
    if exposure.get("path"):
        lines.append(f"- details: {exposure['path']}")
    return "\n".join(lines)


def _write_run_summary(root: Path, case_id: str, command: str,
                       question: str, verdict: str, digest: dict,
                       accuracy: dict | None, candidates: list[Path],
                       skipped_sensitive: int, now: dt.datetime,
                       run_id: str, ak_secrets: list[str],
                       injection: dict | None = None,
                       exposure: dict | None = None) -> Path:
    date = now.strftime("%Y-%m-%d")
    title = f"{date} {case_id} {command} run"
    tiers = digest["tiers"] or {}
    tier_lines = "\n".join(f"- {t}: {n}" for t, n in sorted(tiers.items())) \
        or "- (none recorded)"
    # Self-corrections quote the belief the agent revised — on answer-key
    # cases that revised belief is the recovered secret itself. Scrub it: the
    # run summary is durable, analyst-visible memory.
    corr_lines = "\n".join(
        f"- {c['trigger']}: "
        f"{answer_key.redact(c['prior'][:120], ak_secrets)[0]} → "
        f"{answer_key.redact(c['new'][:120], ak_secrets)[0]}"
        for c in digest["self_corrections"]) or "- (none)"
    acc = ("\n".join(f"- {k}: {v}" for k, v in accuracy.items())
           if accuracy else "- (no ground truth)")
    exp_lines = _exposure_lines(exposure)
    cand_lines = "\n".join(f"- `{p.name}`" for p in candidates) or "- (none)"
    meta = {
        "title": title, "type": "run",
        "created": now.strftime("%Y-%m-%d %H:%M UTC"),
        "updated": now.strftime("%Y-%m-%d %H:%M UTC"),
        "status": "processed", "source_classification": "internal",
        "confidence": "high", "tags": ["agent-run", command],
        "related": [],
        "source": {"type": "agent_run", "url": "",
                   "description": "Generated from active agent run"},
        "origin": {"case_id": case_id, "run_id": run_id, "command": command},
        "entities": {"cases": [case_id], "tools": [], "techniques": [],
                     "actors": [], "cves": []},
    }
    if accuracy:
        meta["accuracy"] = accuracy
    question_clean, _ = secrets.redact(question or "(not recorded)")
    question_clean, _ = answer_key.redact(question_clean, ak_secrets)
    body = (f"# {title}\n\n"
            f"## Goal\n\n{question_clean}\n\n"
            f"## Verdict\n\n{verdict or '(no review)'}\n\n"
            f"## Findings by Tier\n\n{tier_lines}\n\n"
            f"## Accuracy\n\n{acc}\n\n"
            f"## Ground-Truth Exposure\n\n{exp_lines}\n\n"
            f"## Brain Injection\n\n{_injection_lines(injection)}\n\n"
            f"## Self-Corrections\n\n{corr_lines}\n\n"
            f"## Problems Encountered\n\n- system errors in trace: "
            f"{digest['system_errors']}\n\n"
            f"## Open Loops\n\n- (review candidates below)\n\n"
            f"## Memory Candidates Created\n\n{cand_lines}\n\n"
            f"## Sensitive Items Skipped\n\n- flagged confidential: "
            f"{skipped_sensitive}\n")
    dest = root / "logs/runs" / f"{run_id}.md"
    dest.write_text(frontmatter.serialize(meta, body), encoding="utf-8")
    return dest


# ── entry points ─────────────────────────────────────────────────────────

def capture_run(case_dir: Path, case_id: str, question: str,
                review_text: str, verdict: str, command: str = "train") -> dict:
    root = store.brain_root()
    if not root.is_dir():
        raise CaptureError(f"brain directory not found: {root}")
    now = dt.datetime.now(dt.timezone.utc)
    date = now.strftime("%Y-%m-%d")
    timestamp = now.strftime("%Y-%m-%d %H:%M UTC")
    # One id ties the run summary and its candidates together; it doubles as
    # the summary filename stem and the globe's replay-bucket key.
    run_id = f"{now.strftime('%Y-%m-%d-%H%M')}-{store.slugify(case_id)}-{command}"
    trace = _load_trace(case_dir, case_id)
    digest = _trace_digest(trace)
    accuracy = _accuracy(case_dir)
    exposure = gt_exposure.audit_case(case_dir, trace)
    # Answer-key secrets are read server-side only, to scrub candidates — they
    # are never written to any analyst-facing surface.
    ak_secrets = answer_key.load_secrets(case_dir)
    existing = _existing_hashes(root)
    candidates: list[Path] = []
    skipped_sensitive = 0
    dropped_residue = 0

    def stage(ctype, text, why, destination):
        nonlocal dropped_residue
        if len(candidates) >= MAX_CANDIDATES_PER_RUN:
            return
        # Hard-drop case-specific run residue before staging — decision-support
        # signals used to only annotate the candidate; now they suppress it for
        # run-residue types so the brain stops accumulating that noise.
        if _is_run_residue(ctype, text):
            dropped_residue += 1
            return
        p = _stage_candidate(root, case_id, ctype, text, why, destination,
                             existing, date, timestamp, run_id, command,
                             ak_secrets)
        if p is not None:
            candidates.append(p)
            meta, _, _ = frontmatter.parse(p.read_text(encoding="utf-8"))
            nonlocal skipped_sensitive
            if (meta.get("risk") or {}).get("contains_sensitive_data"):
                skipped_sensitive += 1

    # Reviewer recommendations — skipped for STRONG runs (nothing to fix).
    if verdict.upper() != "STRONG":
        for bullet in _recommendation_bullets(review_text or ""):
            ctype, dest = _classify_recommendation(bullet)
            stage(ctype, bullet,
                  "Independent run reviewer recommended this.", dest)

    # evaluate_challenged corrections are the evidence gate doing its job
    # (challenge → re-evidence → pass), not wrong turns, and a run can stage
    # several near-identical ones. Collapse them to at most one aggregate
    # candidate, and only when the volume itself signals gate friction.
    challenged = [c for c in digest["self_corrections"]
                  if c["trigger"] == "evaluate_challenged"]
    for corr in digest["self_corrections"]:
        if corr["trigger"] == "evaluate_challenged":
            continue
        text = (f"Self-correction ({corr['trigger']}): believed "
                f"\"{corr['prior']}\" — corrected to \"{corr['new']}\"")
        stage("issue", text,
              "The agent had to correct itself mid-run; capturing prevents "
              "the same wrong turn next time.", "wiki/concepts")
    if len(challenged) >= CHALLENGED_AGGREGATE_MIN:
        text = (f"The evaluate gate CHALLENGED {len(challenged)} finding "
                f"evaluations this run (each re-evidenced and resolved). "
                f"Individually these are normal gate operation; this volume "
                f"may signal evidence-tier friction worth a workflow look.")
        stage("issue", text,
              "High CHALLENGED volume is a friction signal; individual "
              "challenge retries are protocol noise, not lessons.",
              "wiki/concepts")

    if accuracy:
        text = (f"Accuracy vs ground truth for {case_id}: " +
                ", ".join(f"{k}={v}" for k, v in accuracy.items()))
        stage("accuracy_trend", text,
              "Tracks investigative accuracy across runs of this case.",
              f"wiki/cases/{store.slugify(case_id)}.md")

    summary_path = _write_run_summary(root, case_id, command, question,
                                      verdict, digest, accuracy, candidates,
                                      skipped_sensitive, now, run_id,
                                      ak_secrets,
                                      injection=_injection_manifest(case_dir),
                                      exposure=exposure)
    return {"run_summary": str(summary_path),
            "candidates": len(candidates),
            "candidate_paths": [str(p) for p in candidates],
            "sensitive_flagged": skipped_sensitive,
            "dropped_case_residue": dropped_residue,
            "gt_exposure": (exposure or {}).get("summary")}


def capture_case(case_dir: Path, command: str = "capture") -> dict:
    """Manual capture from a finished run's on-disk artifacts."""
    reviews = sorted(case_dir.glob("reports/*_run_review.md"))
    review_text, verdict, case_id = "", "", case_dir.name
    if reviews:
        review_path = max(reviews, key=lambda p: p.stat().st_mtime)
        review_text = review_path.read_text(encoding="utf-8", errors="replace")
        case_id = review_path.name[:-len("_run_review.md")]
        m = re.search(r"VERDICT[:\s]*([A-Z ]+)", review_text.upper())
        verdict = m.group(1).strip() if m else ""
    else:
        traces = sorted(case_dir.glob("analysis/*_trace.json"))
        if not traces:
            raise CaptureError(
                f"nothing to capture under {case_dir} — no run review or "
                "trace found (run `atlas train` first)")
        case_id = traces[-1].name[:-len("_trace.json")]
    return capture_run(case_dir, case_id, question="",
                       review_text=review_text, verdict=verdict,
                       command=command)
