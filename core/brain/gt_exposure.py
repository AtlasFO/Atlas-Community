"""Ground-truth exposure audit: was each expected answer ever SEEN in tool
output, and did it make it into a finding?

An accuracy false-negative is opaque: it can mean the evidence was never
surfaced (a tooling/routing gap — buy or route a parser) or that it scrolled
past the analyst and never became a finding (an attention/reasoning gap — fix
prompting, brain injection, or gates). Those are different remediations, so
the audit splits every ground-truth item into:

    reported               — matched a recorded finding (accuracy TP)
    reported-bundled       — stated by a sentence of a finding the matcher
                             credited to another item (accuracy FN, but the
                             fact is on record — a grading artifact, not a gap)
    surfaced-not-reported  — appeared in some tool output, no finding
    never-surfaced         — no tool output ever contained it
    unassessable           — the item carries no probe-able identifier

"Surfaced" is a substring scan of tool_call trace entries with probes derived
from the item's discriminative entities (core.entities): hashes, IPs, emails,
filenames, URLs, flags, timestamps. Prose-only GT items are unassessable —
better honest than guessed.

Answer-key hygiene: this module runs SERVER-SIDE after a run. The JSON it
writes into analysis/ contains item ids and classifications; explicit
answer-key secret values are redacted in the output (the probes exist only
in memory during the scan).
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from core import entities as _entities
from core.brain import answer_key

_MIN_PROBE_LEN = 4


def _probes_from_text(text: str) -> set[str]:
    """Case-insensitive substring probes from a GT item's description."""
    probes: set[str] = set()
    for ent in _entities.discriminative(_entities.extract(text or "")):
        etype, _, value = ent.partition(":")
        if etype == "ts":
            probes.add(value)                      # 2023-01-24T09:15
            probes.add(value.replace("T", " "))    # 2023-01-24 09:15
        elif etype == "account":
            probes.add(value.rsplit("/", 1)[-1])   # the username
        else:
            probes.add(value)
    return {p.lower() for p in probes if len(p) >= _MIN_PROBE_LEN}


_STDOUT_FILE_CAP = 262144  # 256 KiB per spilled output — bound the read


def _entry_text(entry: dict) -> str:
    """Searchable evidence text for a tool_call: tool OUTPUT only.

    Deliberately EXCLUDES `cmd` — that is what the agent typed, not what a
    tool returned. Counting the command would let a run that already knows an
    answer make any probe 'surface' by naming the entity in an argument (the
    parroting signal would then never fire). Output is stored under
    `stdout_excerpt` (a 600-char excerpt, committed in the trace) plus, for
    large outputs, a gitignored `stdout_file` spill. The excerpt alone is the
    committed, CI-reproducible corpus; the spill is read as a superset when
    present (local / live runs), never required. The legacy `stdout` key is
    kept for old traces that inlined full output."""
    parts = [str(entry.get(k) or "") for k in
             ("stdout_excerpt", "stdout", "stderr")]
    spill = entry.get("stdout_file")
    if spill:
        try:
            with open(spill, encoding="utf-8", errors="replace") as fh:
                parts.append(fh.read(_STDOUT_FILE_CAP))
        except OSError:
            pass  # gitignored / absent in this checkout — excerpt is enough
    return "\n".join(p for p in parts if p).lower()


def _first_hit(probes: set[str], tool_calls: list[tuple[int, str, str]]):
    """(call_id, mcp_tool) of the earliest tool output containing a probe."""
    for call_id, tool, text in tool_calls:
        for p in probes:
            if p in text:
                return call_id, tool
    return None, None


def _surface_corpus(entries: list[dict]) -> list[tuple[int, str, str]]:
    """(call_id, tool, text) of everything that counts as evidence INPUT.

    tool_call output always counts. investigation_narration counts only in
    the preamble — entries before the first agent-driven entry (reason/tool/
    finding/dair). Live-monitoring investigations open with a system-written
    alert bundle narration that IS the evidence surface (DEMO-LIVE's YARA/
    baseline detections arrive that way); mid-run narration is the agent's
    own text and would mask parroting if it counted."""
    agent_types = {"tool_call", "reason_call", "dair_call", "finding",
                   "call_initiated", "self_correction"}
    first_agent = min((e.get("call_id", 0) for e in entries
                       if e.get("type") in agent_types), default=None)
    corpus = []
    for e in entries:
        etype = e.get("type")
        if etype == "tool_call":
            corpus.append((e.get("call_id", 0), e.get("mcp_tool", ""),
                           _entry_text(e)))
        elif (etype == "investigation_narration"
              and (first_agent is None
                   or e.get("call_id", 0) < first_agent)):
            corpus.append((e.get("call_id", 0), "(alert-preamble)",
                           str(e.get("content") or "").lower()))
    return sorted(corpus, key=lambda t: t[0])


def audit(gt: dict, entries: list[dict], match_threshold: float = 0.30) -> dict:
    from tools.accuracy import compare_findings

    findings = [e for e in entries if e.get("type") == "finding"]
    tool_calls = _surface_corpus(entries)
    findings_text = "\n".join(
        f.get("description", "") for f in findings).lower()

    cmp_result = compare_findings(gt, findings, match_threshold)
    reported_ids = ({tp["ground_truth_id"] for tp in
                     cmp_result.get("true_positives", [])}
                    if not cmp_result.get("unscorable") else set())
    bundled_ids = ({b["ground_truth_id"] for b in cmp_result.get("bundled", [])}
                   if not cmp_result.get("unscorable") else set())

    items = []
    for gt_item in gt.get("expected_findings", []) or []:
        item_id = gt_item.get("id", "")
        probes = _probes_from_text(gt_item.get("description", ""))
        first_cid, first_tool = _first_hit(probes, tool_calls)
        if item_id in reported_ids:
            cls = "reported"
        elif item_id in bundled_ids:
            cls = "reported-bundled"
        elif first_cid is not None:
            cls = "surfaced-not-reported"
        elif not probes:
            cls = "unassessable"
        else:
            cls = "never-surfaced"
        items.append({
            "id": item_id, "kind": "expected_finding",
            "description": gt_item.get("description", ""),
            "classification": cls,
            "first_seen_call_id": first_cid,
            "first_seen_tool": first_tool,
            "probe_count": len(probes),
        })

    # CTF-style keys and explicit secret lists: each secret is an item of its
    # own. Value stays out of the written report (redacted id only).
    for n, secret in enumerate(answer_key.extract_secrets(gt), 1):
        probe = secret.lower()
        if len(probe) < _MIN_PROBE_LEN:
            continue
        first_cid, first_tool = _first_hit({probe}, tool_calls)
        if probe in findings_text:
            cls = "reported"
        elif first_cid is not None:
            cls = "surfaced-not-reported"
        else:
            cls = "never-surfaced"
        items.append({
            "id": f"secret#{n}", "kind": "answer_key_secret",
            "description": answer_key.REDACTION,
            "classification": cls,
            "first_seen_call_id": first_cid,
            "first_seen_tool": first_tool,
            "probe_count": 1,
        })

    counts: dict[str, int] = {}
    for it in items:
        counts[it["classification"]] = counts.get(it["classification"], 0) + 1
    return {
        "case_id": gt.get("case_id", ""),
        "generated_utc": _dt.datetime.now(_dt.timezone.utc)
                            .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "items": items,
        "summary": counts,
        "scorable": not cmp_result.get("unscorable", False),
    }


def audit_case(case_dir: Path, trace: dict) -> dict | None:
    """Run the audit for a case and persist analysis/gt_exposure.json.

    Best-effort, never raises: no ground truth or no trace means no audit —
    never a failed capture.
    """
    try:
        gt_path = answer_key._find_ground_truth(Path(case_dir))
        if gt_path is None:
            return None
        gt = json.loads(gt_path.read_text(encoding="utf-8"))
        entries = trace.get("entries") or []
        if not isinstance(gt, dict) or not entries:
            return None
        result = audit(gt, entries)
        out = Path(case_dir) / "analysis" / "gt_exposure.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        result["path"] = str(out)
        return result
    except Exception:
        return None


def audit_run_dir(gt_dir: Path, run_dir: Path) -> dict | None:
    """audit_case generalized to a split GT/trace source: GT from the real
    case dir, trace from an --output-dir mirror (whose ground_truth.json is
    deliberately not mirrored). Persists <run_dir>/analysis/gt_exposure.json.
    Best-effort, never raises."""
    try:
        gt_path = answer_key._find_ground_truth(Path(gt_dir))
        if gt_path is None:
            return None
        gt = json.loads(gt_path.read_text(encoding="utf-8"))
        candidates = sorted(Path(run_dir).glob("analysis/*_trace.json"))
        if not candidates:
            candidates = sorted(Path(run_dir).glob("reports/*_trace.json"))
        if not candidates or not isinstance(gt, dict):
            return None
        trace_path = max(candidates, key=lambda p: p.stat().st_mtime)
        data = json.loads(trace_path.read_text(encoding="utf-8"))
        entries = (data.get("entries") or []) if isinstance(data, dict) \
            else data
        if not entries:
            return None
        result = audit(gt, entries)
        out = Path(run_dir) / "analysis" / "gt_exposure.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        result["path"] = str(out)
        return result
    except Exception:
        return None


def integrity_summary(result: dict | None) -> dict | None:
    """Cheat-signal distillation of an audit result for graded-run records.

    parroted: GT items REPORTED as findings whose discriminative entities
    never appeared in any tool output — the finding's content cannot have
    come from the evidence trail. answer_key_hits: answer-key secrets that
    showed up in findings or tool output at all."""
    if not result:
        return None
    if not result.get("scorable", False):
        return {"scorable": False}
    items = result.get("items") or []
    return {
        "scorable": True,
        "counts": result.get("summary") or {},
        "parroted": [it["id"] for it in items
                     if it.get("kind") == "expected_finding"
                     and it.get("classification") == "reported"
                     and it.get("first_seen_call_id") is None
                     and it.get("probe_count", 0) > 0],
        "answer_key_hits": [it["id"] for it in items
                            if it.get("kind") == "answer_key_secret"
                            and it.get("classification") in
                            ("reported", "surfaced-not-reported")],
    }
