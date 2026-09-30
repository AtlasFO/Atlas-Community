"""Investigation-wide Brain learning (quality-first).

After a completed investigation, analyse durable case artifacts and stage a
small number of *reusable* forensic lessons. Never blocks the investigator —
callers either run this synchronously (``atlas brain learn``) or spawn it via
``core.brain.background``.

Preserves all capture/approve safety gates. Prefer ≤3 excellent candidates
over many mediocre ones.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable

from core.brain import answer_key, capture, frontmatter, identifiers, store

# Hard ceiling — prefer ≤3 excellent candidates; never flood the review inbox.
MAX_LEARN_CANDIDATES = 3
# Drop anything below high confidence — quality over quantity.
_CONF_RANK = {"high": 3, "medium": 2, "low": 1}
MIN_CONFIDENCE = "high"
# Novelty: skip if an existing wiki note already matches strongly.
_NOVELTY_SCORE_FLOOR = 14.0
_DIGEST_CHAR_CAP = 55_000
_MIN_BODY_CHARS = 160

# Low-value / preference / one-off shapes that are not Brain material.
_TRIVIAL_PATTERNS = [
    re.compile(r"(?i)\b(?:always|never)\s+(?:use|pass|add|include)\s+--?\w+\b"),
    re.compile(r"(?i)\bprefer\s+.{0,40}\s+over\s+.{0,40}$"),
    re.compile(r"(?i)\b(?:this|the)\s+(?:case|run|engagement|ticket)\b"),
    re.compile(r"(?i)\bnext\s+run\b|\bfollow[\s-]?up\b|\btodo\b"),
    re.compile(r"(?i)\bi\s+(?:found|noticed|observed)\b"),
    re.compile(r"(?i)\bcustomer[\s-]specific\b|\bclient[\s-]specific\b"),
]

_DEST_BY_TYPE = {
    "tool_gotcha": "wiki/tools",
    "technique_insight": "wiki/techniques",
    "workflow": "wiki/concepts",
    "detection_idea": "wiki/techniques",
    "methodology": "wiki/concepts",
    "correlation": "wiki/concepts",
    "issue": "wiki/concepts",
}

LEARN_SYSTEM_PROMPT = """\
You extract reusable DFIR Lessons Learned for Atlas's cross-case Brain.

You receive a digest of ONE finished investigation. Your job is NOT to
summarise the case. Your job is to propose at most a few durable lessons an
experienced forensic analyst would write in a personal notebook after the job.

Two knowledge kinds (use exactly these strings):
- lesson_learned — methodology / workflow / tool usage we should do better next time
- knowledge_gained — reusable forensic knowledge (behaviour patterns, persistence,
  overlooked artifacts, useful correlations, detection ideas)

GOOD candidates (general, reusable, non-obvious):
- Tool limitations and failure modes that change investigative outcomes
- Investigation methodology improvements with clear forensic rationale
- Malware/family behaviour patterns (no case IOCs)
- Common persistence mechanisms and where to look
- Frequently overlooked artifacts
- Useful cross-artifact correlations
- Detection ideas stated as patterns

BAD candidates (never emit — empty list is better):
- Hostnames, IPs, hashes, emails, usernames, customer names
- Case IDs, ticket numbers, one-off observations
- Temporary investigation tasks or "next run" todos
- Trivial command-line preferences ("always pass --json")
- Style nits without forensic consequence
- Verbatim ground-truth / answer-key material
- Anything that only applies to this one engagement
- Restating common DFIR textbook facts with no investigation-specific insight

Quality bar (strict):
- Prefer 0–3 excellent lessons. Zero is correct when nothing is reusable.
- Only emit confidence "high" when you would stake your reputation on the lesson.
- Use "medium" only for plausible but weaker lessons (they are dropped by the gate).
- Never invent tools or TTPs not supported by the digest.
- Each body must explain WHY it matters for a future different case.

Output ONLY valid JSON (no markdown fences) with this shape:
{
  "lessons": [
    {
      "title": "short noun-phrase title",
      "body": "1–3 paragraphs of generalized lesson text",
      "knowledge_kind": "lesson_learned" | "knowledge_gained",
      "candidate_type": "tool_gotcha" | "technique_insight" | "workflow" | "detection_idea" | "methodology" | "correlation",
      "suggested_destination": "wiki/tools" | "wiki/techniques" | "wiki/concepts",
      "confidence": "high" | "medium" | "low",
      "why_exists": "why this was extracted from THIS investigation",
      "origin_sources": ["claim_graph", "report", "review", "..."],
      "supporting_evidence": "claim/finding ids or short paraphrases — NO secrets/IOCs",
      "why_reusable": "why this helps a DIFFERENT future case"
    }
  ]
}
"""


class LearnError(Exception):
    pass


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _clip(text: str, n: int) -> str:
    text = (text or "").strip()
    if len(text) <= n:
        return text
    return text[: n - 1] + "…"


def _write_status(case_dir: Path, payload: dict) -> Path:
    atlas = case_dir / ".atlas"
    atlas.mkdir(parents=True, exist_ok=True)
    path = atlas / "brain_learn.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    return path


def build_investigation_digest(
        case_dir: Path, case_id: str, *,
        question: str = "",
        review_text: str = "",
        verdict: str = "") -> str:
    """Assemble a bounded text digest of the finished investigation."""
    parts: list[str] = [
        f"# Investigation digest — {case_id}",
        f"Question: {_clip(question or '(not recorded)', 800)}",
        f"Reviewer verdict: {verdict or '(none)'}",
        "",
    ]

    # Claim graph — current beliefs only (titles/summaries).
    cg = _read_json(case_dir / ".atlas" / "claim_graph.json")
    if isinstance(cg, dict):
        nodes = cg.get("nodes") or {}
        lines = []
        for nid, node in list(nodes.items())[:80]:
            if not isinstance(node, dict):
                continue
            kind = str(node.get("kind") or "")
            status = str(node.get("status") or "")
            if kind not in ("claim", "conclusion", "hypothesis",
                            "observation", "conflict"):
                continue
            if status in ("withdrawn", "superseded"):
                continue
            summary = (node.get("summary") or node.get("title")
                       or node.get("text") or "")
            lines.append(f"- [{kind}/{status}] {nid}: {_clip(str(summary), 220)}")
        parts.append("## Claim graph (current beliefs)")
        parts.append("\n".join(lines) or "- (empty)")
        parts.append("")

    mem = _read_json(case_dir / ".atlas" / "investigation_memory.json")
    if isinstance(mem, dict):
        parts.append("## Investigation memory (summary keys)")
        for key in ("open_questions", "analyst_context", "working_theory",
                    "key_findings", "summary"):
            val = mem.get(key)
            if val:
                parts.append(f"### {key}")
                parts.append(_clip(json.dumps(val, ensure_ascii=False)
                                   if not isinstance(val, str) else val, 4000))
        parts.append("")

    tasks = _read_json(case_dir / ".atlas" / "investigation_tasks.json")
    if isinstance(tasks, dict):
        items = tasks.get("tasks") or tasks.get("items") or []
        tlines = []
        for t in items[:40]:
            if not isinstance(t, dict):
                continue
            tlines.append(
                f"- [{t.get('status', '?')}] {_clip(str(t.get('title') or t.get('id') or ''), 160)}")
        parts.append("## Investigation tasks")
        parts.append("\n".join(tlines) or "- (none)")
        parts.append("")

    trace = capture._load_trace(case_dir, case_id)
    digest = capture._trace_digest(trace)
    findings = [e for e in (trace.get("entries") or [])
                if e.get("type") == "finding"][:40]
    flines = []
    for f in findings:
        flines.append(
            f"- [{f.get('confidence', '?')}] "
            f"{_clip(str(f.get('title') or f.get('summary') or f.get('text') or ''), 200)}")
    parts.append("## Findings (trace)")
    parts.append("\n".join(flines) or "- (none)")
    parts.append("")
    parts.append("## Self-corrections")
    corr = digest.get("self_corrections") or []
    parts.append("\n".join(
        f"- {c.get('trigger')}: {_clip(c.get('prior', ''), 100)} → "
        f"{_clip(c.get('new', ''), 100)}" for c in corr[:20]) or "- (none)")
    parts.append("")

    # Final report — prefer projected / final md.
    report_text = ""
    for pattern in ("reports/*_final*.md", "reports/*report*.md",
                    "reports/*.md"):
        for p in sorted(case_dir.glob(pattern),
                        key=lambda x: x.stat().st_mtime, reverse=True):
            if "run_review" in p.name:
                continue
            try:
                report_text = p.read_text(encoding="utf-8", errors="replace")
                parts.append(f"## Report excerpt ({p.name})")
                parts.append(_clip(report_text, 12_000))
                parts.append("")
                break
            except OSError:
                continue
        if report_text:
            break

    if review_text:
        parts.append("## Independent run review")
        parts.append(_clip(review_text, 8_000))
        parts.append("")
    else:
        reviews = sorted(case_dir.glob("reports/*_run_review.md"))
        if reviews:
            rp = max(reviews, key=lambda p: p.stat().st_mtime)
            try:
                parts.append(f"## Independent run review ({rp.name})")
                parts.append(_clip(rp.read_text(encoding="utf-8",
                                                errors="replace"), 8_000))
                parts.append("")
            except OSError:
                pass

    text = "\n".join(parts)
    return _clip(text, _DIGEST_CHAR_CAP)


def _extract_json_object(raw: str) -> dict:
    text = (raw or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        raise LearnError("learner returned no JSON object")
    data = json.loads(m.group(0))
    if not isinstance(data, dict):
        raise LearnError("learner JSON root must be an object")
    return data


def _normalize_lesson(raw: dict) -> dict | None:
    if not isinstance(raw, dict):
        return None
    body = str(raw.get("body") or "").strip()
    title = str(raw.get("title") or "").strip()
    if not body or len(body) < _MIN_BODY_CHARS:
        return None
    kind = str(raw.get("knowledge_kind") or "").strip().lower()
    if kind not in ("lesson_learned", "knowledge_gained"):
        # Infer from candidate_type rather than drop.
        ctype0 = str(raw.get("candidate_type") or "").lower()
        kind = ("lesson_learned"
                if ctype0 in ("workflow", "methodology", "tool_gotcha", "issue")
                else "knowledge_gained")
    ctype = str(raw.get("candidate_type") or "workflow").strip().lower()
    if ctype not in _DEST_BY_TYPE:
        ctype = "workflow"
    dest = str(raw.get("suggested_destination") or _DEST_BY_TYPE[ctype]).strip()
    if not dest.startswith("wiki/"):
        dest = _DEST_BY_TYPE[ctype]
    # Never learn into environments or cases from this path.
    if dest.startswith("wiki/environments") or dest.startswith("wiki/cases"):
        dest = _DEST_BY_TYPE[ctype]
    conf = str(raw.get("confidence") or "medium").strip().lower()
    if conf not in _CONF_RANK:
        conf = "medium"
    sources = raw.get("origin_sources") or []
    if isinstance(sources, str):
        sources = [sources]
    sources = [str(s).strip() for s in sources if str(s).strip()][:8]
    return {
        "title": title or body[:70],
        "body": body,
        "knowledge_kind": kind,
        "candidate_type": ctype,
        "suggested_destination": dest.rstrip("/"),
        "confidence": conf,
        "why_exists": str(raw.get("why_exists") or "").strip()
                      or "Extracted from the completed investigation digest.",
        "origin_sources": sources or ["investigation"],
        "supporting_evidence": str(raw.get("supporting_evidence") or "").strip(),
        "why_reusable": str(raw.get("why_reusable") or "").strip()
                        or "Generalized forensic practice applicable to future cases.",
    }


def _passes_quality(lesson: dict, existing: set[str],
                    ak_secrets: list[str]) -> tuple[bool, str]:
    conf = lesson["confidence"]
    if _CONF_RANK.get(conf, 0) < _CONF_RANK[MIN_CONFIDENCE]:
        return False, "confidence_below_floor"
    body = (lesson.get("body") or "").strip()
    if len(body) < _MIN_BODY_CHARS:
        return False, "body_too_short"
    why_r = (lesson.get("why_reusable") or "").strip()
    if len(why_r) < 40:
        return False, "weak_reusability"
    core = f"{lesson['title']}\n{body}"
    for pat in _TRIVIAL_PATTERNS:
        if pat.search(core):
            return False, "trivial_or_case_bound"
    text = f"{core}\n{why_r}"
    if capture._is_run_residue(lesson["candidate_type"], text):
        return False, "case_residue"
    if capture._review_hints(text)["likely_case_specific"]:
        # Public destinations require generalization; drop rather than stage junk.
        return False, "likely_case_specific"
    if identifiers.scan_text(text):
        return False, "identifiers"
    scrubbed, ak_hits = answer_key.redact(text, ak_secrets)
    if ak_hits:
        return False, "answer_key"
    h = capture._content_hash(scrubbed)
    if h in existing:
        return False, "duplicate_hash"
    # Novelty vs durable wiki (not inbox).
    try:
        from core.brain.search import search
        hits = search(f"{lesson['title']} {lesson['body'][:240]}",
                      types=["concept", "tool", "technique"], limit=3)
        if hits and hits[0].score >= _NOVELTY_SCORE_FLOOR:
            return False, f"not_novel:{hits[0].rel_path}"
    except Exception:
        pass
    return True, "ok"


def extract_lessons_via_llm(digest: str, chat: Callable[..., Any]) -> list[dict]:
    """Call ``chat(messages)`` and return normalized lessons."""
    resp = chat(
        [{"role": "system", "content": LEARN_SYSTEM_PROMPT},
         {"role": "user", "content": digest}])
    content = getattr(resp, "content", None)
    if content is None and isinstance(resp, dict):
        content = resp.get("content")
    data = _extract_json_object(str(content or ""))
    raw_lessons = data.get("lessons") or []
    if not isinstance(raw_lessons, list):
        raise LearnError("lessons must be a list")
    out: list[dict] = []
    for item in raw_lessons[:MAX_LEARN_CANDIDATES + 2]:
        norm = _normalize_lesson(item)
        if norm:
            out.append(norm)
    return out[:MAX_LEARN_CANDIDATES]


def _default_chat():
    from agent.llm import LLMHubClient
    from agent.review import reviewer_model, reviewer_provider
    client = LLMHubClient(provider=reviewer_provider(), model=reviewer_model())
    return client.chat


def prepare_learn_inputs(
        case_dir: Path | str,
        case_id: str = "",
        *,
        question: str = "",
        review_text: str = "",
        verdict: str = "") -> dict:
    """The half of learning that reads the case: the adversary-tool lexicon
    and the digest (claim graph, memory, tasks, trace, reports), written to
    .atlas/brain_learn_digest.md. A finishing run calls it before it releases
    the run lock, because a fresh start of the case, possible from then on,
    moves the trace and wipes analysis/ and reports/ under a reader. Local
    reads only, no model call. Returns {"digest_file", "lexicon_notes"}."""
    case_dir = Path(case_dir).resolve()
    case_id = case_id or case_dir.name
    # Names this run flagged by behaviour go straight into the lexicon: no
    # reviewer, no model call and no user interaction, so the lexicon stays
    # current even when the LLM half of learning is unavailable or skipped.
    try:
        from core.ioc_catalog import capture_adversary_tools
        lexicon_notes = len(capture_adversary_tools(case_dir, case_id))
    except Exception:  # noqa: BLE001 - never let the lexicon break learning
        lexicon_notes = 0
    if not review_text:
        reviews = sorted(case_dir.glob("reports/*_run_review.md"))
        if reviews:
            rp = max(reviews, key=lambda p: p.stat().st_mtime)
            review_text = rp.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"VERDICT[:\s]*([A-Z ]+)", review_text.upper())
            verdict = verdict or (m.group(1).strip() if m else "")
    digest = build_investigation_digest(
        case_dir, case_id, question=question,
        review_text=review_text, verdict=verdict)
    digest_path = case_dir / ".atlas" / "brain_learn_digest.md"
    digest_path.parent.mkdir(parents=True, exist_ok=True)
    digest_path.write_text(digest + "\n", encoding="utf-8")
    return {"digest_file": str(digest_path), "lexicon_notes": lexicon_notes}


def learn_from_investigation(
        case_dir: Path | str,
        case_id: str = "",
        *,
        question: str = "",
        review_text: str = "",
        verdict: str = "",
        command: str = "learn",
        chat: Callable[..., Any] | None = None,
        skip_llm: bool = False,
        prepared: dict | None = None) -> dict:
    """Run the full learning pass and stage qualifying candidates.

    ``prepared`` is prepare_learn_inputs' result when the finishing run
    already read the case; without it the case is read here.
    ``skip_llm`` is for tests — stages nothing after building the digest.
    """
    case_dir = Path(case_dir).resolve()
    if not case_dir.is_dir():
        raise LearnError(f"case dir not found: {case_dir}")
    case_id = case_id or case_dir.name
    root = store.brain_root()
    if not root.is_dir():
        raise LearnError(f"brain directory not found: {root}")

    status = {
        "status": "running",
        "case_id": case_id,
        "lexicon_notes": int((prepared or {}).get("lexicon_notes") or 0),
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "candidates": 0,
        "dropped": {},
        "error": None,
    }
    _write_status(case_dir, status)

    try:
        if prepared is None:
            prepared = prepare_learn_inputs(
                case_dir, case_id, question=question,
                review_text=review_text, verdict=verdict)
            status["lexicon_notes"] = prepared["lexicon_notes"]
        digest_path = Path(prepared["digest_file"])
        digest = digest_path.read_text(encoding="utf-8").removesuffix("\n")

        if skip_llm:
            status.update({"status": "skipped_llm", "digest": str(digest_path),
                           "finished_at": dt.datetime.now(dt.timezone.utc).isoformat()})
            _write_status(case_dir, status)
            return status

        chat_fn = chat or _default_chat()
        lessons = extract_lessons_via_llm(digest, chat_fn)

        now = dt.datetime.now(dt.timezone.utc)
        date = now.strftime("%Y-%m-%d")
        timestamp = now.strftime("%Y-%m-%d %H:%M UTC")
        run_id = (f"{now.strftime('%Y-%m-%d-%H%M')}-"
                  f"{store.slugify(case_id)}-learn")
        ak_secrets = answer_key.load_secrets(case_dir)
        existing = capture._existing_hashes(root)
        dropped: dict[str, int] = {}
        staged: list[str] = []

        for lesson in lessons:
            ok, reason = _passes_quality(lesson, existing, ak_secrets)
            if not ok:
                dropped[reason] = dropped.get(reason, 0) + 1
                continue
            path = capture._stage_candidate(
                root, case_id, lesson["candidate_type"], lesson["body"],
                lesson["why_exists"], lesson["suggested_destination"],
                existing, date, timestamp, run_id, command, ak_secrets,
                title=lesson["title"],
                confidence=lesson["confidence"],
                knowledge_kind=lesson["knowledge_kind"],
                why_reusable=lesson["why_reusable"],
                supporting_evidence=lesson["supporting_evidence"],
                origin_sources=lesson["origin_sources"],
                learning_phase="investigation_learn",
                source_description=(
                    f"Background investigation learn from {case_id}"),
            )
            if path is None:
                dropped["stage_failed"] = dropped.get("stage_failed", 0) + 1
            else:
                staged.append(str(path))

        status.update({
            "status": "completed",
            "digest": str(digest_path),
            "candidates": len(staged),
            "candidate_paths": staged,
            "dropped": dropped,
            "lessons_considered": len(lessons),
            "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        })
        _write_status(case_dir, status)
        return status
    except Exception as e:
        status.update({
            "status": "failed",
            "error": f"{e.__class__.__name__}: {e}",
            "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        })
        _write_status(case_dir, status)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract high-quality Brain lessons from a finished case")
    parser.add_argument("--case", required=True, help="case directory")
    parser.add_argument("--case-id", default="")
    parser.add_argument("--question", default="")
    parser.add_argument("--review", default="",
                        help="path to run review markdown (optional)")
    parser.add_argument("--verdict", default="")
    parser.add_argument("--command", default="learn")
    parser.add_argument("--job-file", default="",
                        help="JSON job file written by background.spawn")
    parser.add_argument("--digest-only", action="store_true",
                        help="build digest + status without calling an LLM")
    args = parser.parse_args(argv)
    # Inherited from the run that spawned this job; the learner's own calls
    # are told apart by their command; a learn started by hand records under
    # the case it names.
    from core import usage_ledger
    if usage_ledger.current().get("case_id"):
        usage_ledger.configure(command="brain_learn")
    else:
        from core.paths import detect_case_id
        case_path = Path(args.case).expanduser()
        usage_ledger.configure(
            case_id=detect_case_id(case_path) or case_path.name,
            run_id="learn-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
            command="brain_learn")

    question, review_text, verdict, command = (
        args.question, "", args.verdict, args.command)
    case_id = args.case_id
    prepared = None
    if args.job_file:
        job = _read_json(Path(args.job_file)) or {}
        question = str(job.get("question") or question)
        review_text = str(job.get("review_text") or "")
        verdict = str(job.get("verdict") or verdict)
        command = str(job.get("command") or command)
        case_id = str(job.get("case_id") or case_id)
        if job.get("digest_file") and Path(job["digest_file"]).is_file():
            prepared = {"digest_file": job["digest_file"],
                        "lexicon_notes": job.get("lexicon_notes") or 0}
    if args.review:
        review_text = Path(args.review).read_text(encoding="utf-8",
                                                  errors="replace")
        prepared = None

    try:
        result = learn_from_investigation(
            args.case, case_id=case_id, question=question,
            review_text=review_text, verdict=verdict, command=command,
            skip_llm=args.digest_only, prepared=prepared)
    except LearnError as e:
        print(f"atlas brain learn: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"atlas brain learn failed: {e}", file=sys.stderr)
        return 1
    print(json.dumps({k: result.get(k) for k in
                      ("status", "candidates", "dropped", "error",
                       "candidate_paths")}, ensure_ascii=False))
    return 0 if result.get("status") in ("completed", "skipped_llm") else 1


if __name__ == "__main__":
    raise SystemExit(main())
