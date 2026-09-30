"""Accuracy framework: compare trace findings against a case ground truth.

Produces a confusion matrix (TP/FP/FN), precision/recall/F1, and a list of
confidence downgrades — findings recorded below the ground truth's minimum tier.
Used to produce an accuracy self-assessment against a curated ground truth.
"""
import json
import os
import re
from fastmcp import FastMCP
from core.paths import assert_output_safe
from core import entities as _entities
from core import output_safe

mcp = FastMCP("accuracy")

# Bumped whenever matching semantics change, so stored accuracy numbers are
# comparable only within a version. v2 = canonical-entity matching on top of
# token containment.
MATCHER_VERSION = 2


_TIER_RANK = {
    "CONFIRMED": 4,
    "LIKELY": 3,
    "SUSPECTED": 2,
    "UNCONFIRMED": 1,
}

# A CTF answer key stores MD5/SHA-style digests or short flag tokens as the
# expected answer per question, never finding-shaped prose. Used only to make
# the "unscorable" reason message specific; the unscorable decision itself
# keys on the absence of `expected_findings`.
_ANSWER_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")


def _looks_like_answer_hash(value: str) -> bool:
    """True for a bare hex digest (md5/sha1/sha256) — a CTF grader answer."""
    return bool(_ANSWER_HASH_RE.match(value.strip()))


# Function words excluded from matching. Kept minimal and generic — no
# DFIR-domain terms, which carry signal (e.g. "deleted", "confidential").
_STOPWORDS = frozenset("""
the and for from with was were are has have had that this these those not its
into onto via per during between then than when where which while been being
also after before both each all any but his her their our your can could did
does doing done down out over under only same some such more most other own
""".split())

# No backslash in the token class: UNC paths and Windows paths split into
# components so \\10.11.11.128\secured_drive matches a finding that cites the
# IP or the share name separately.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_.#@:-]{3,}")
# fat32 / utc-5-style tokens also contribute their alpha stem (fat, utc) so a
# ground truth saying "FAT" matches a finding saying "FAT32".
_NUMERIC_SUFFIX_RE = re.compile(r"^([a-z]{3,})\d{1,4}$")

_HS_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HS_MITRE = re.compile(r"^t1\d{3}(?:\.\d{3})?$")
_HS_FILENAME = re.compile(r"^[\w#-]+\.[a-z0-9]{1,5}$")
_HS_IDENTIFIER = re.compile(r"^(?=.*\d)[a-z0-9]{8,}$")


def _tokens(text: str) -> set[str]:
    """Lowercase tokens ≥3 chars from a description, minus stopwords.

    Used as the matching primitive between trace findings and ground-truth
    items. We deliberately avoid heavyweight NLP — token-set containment is
    enough for validation against a curated ground truth.
    """
    toks = {t.strip(".:-") for t in _TOKEN_RE.findall(text.lower())}
    toks = {t for t in toks if len(t) >= 3 and t not in _STOPWORDS}
    stems = set()
    for t in toks:
        m = _NUMERIC_SUFFIX_RE.match(t)
        if m:
            stems.add(m.group(1))
    return toks | stems


def _is_high_signal(token: str) -> bool:
    """Tokens that are near-unique identifiers: device serials, filenames,
    email addresses, IPs, MITRE technique IDs. Sharing one of these between a
    ground-truth item and a finding is strong evidence of a real match."""
    return bool(
        "@" in token
        or _HS_IP.match(token)
        or _HS_MITRE.match(token)
        or (len(token) >= 6 and _HS_FILENAME.match(token))
        or _HS_IDENTIFIER.match(token)
    )


def _match_detail(reference: str, finding: str) -> tuple[float, str]:
    """Asymmetric containment plus canonical-entity matching.

    Token layer (v1): fraction of reference tokens covered by the finding.
    The reference (ground-truth item or negative assertion) is one curated
    line; trace findings are long, evidence-rich paragraphs. Symmetric overlap
    (Jaccard) fails here — the finding's extra tokens inflate the union and
    cap the score near zero no matter how completely the reference is covered.
    Containment scores 1.0 when every reference token appears in the finding,
    regardless of finding length. Requires ≥2 shared tokens so a single
    generic word can't match a very short reference.

    Entity layer (v2): both texts run through core.entities; a shared
    canonical entity (same hash regardless of case, same path regardless of
    separator style, same IP regardless of formatting) is near-proof the two
    describe the same artifact — it suffices on its own and boosts the score
    the same way a shared high-signal token does.

    Returns (score, match_quality) where match_quality is "entity" when a
    shared canonical entity anchored the match, "token" for pure prose
    overlap, "none" below any signal.
    """
    ta, tb = _tokens(reference), _tokens(finding)
    if not ta or not tb:
        return 0.0, "none"
    shared = ta & tb
    high_signal = sum(1 for t in shared if _is_high_signal(t))
    shared_entities = (_entities.discriminative(_entities.extract(reference))
                       & _entities.discriminative(_entities.extract(finding)))
    if len(shared) < 2 and not high_signal and not shared_entities:
        return 0.0, "none"
    score = len(shared) / len(ta)
    if high_signal:
        score = min(1.0, score + 0.25 * high_signal)
    if shared_entities:
        score = min(1.0, score + 0.35 * len(shared_entities))
        return score, "entity"
    return score, "token"


def _match_score(reference: str, finding: str) -> float:
    """Match score between a curated reference line and a trace finding."""
    return _match_detail(reference, finding)[0]


def _meets_min_tier(actual: str, minimum: str) -> bool:
    """True if actual confidence tier is at or above minimum."""
    return _TIER_RANK.get(actual.upper(), 0) >= _TIER_RANK.get(minimum.upper(), 0)


# A negative assertion ("no persistence via Run keys") must be satisfied by a
# finding that CLAIMS ABSENCE — not by a positive finding that merely shares
# its tokens ("persistence via Run keys exists"). UNCONFIRMED tier is the
# conventional absence marker, but a verified absence is legitimately recorded
# LIKELY/CONFIRMED ("no exfil via HTTP — verified against full pcap"), so any
# tier qualifies when the description itself is negation-shaped.
_NEGATION_RE = re.compile(
    r"\b(?:no|not|none|never|without|absent|absence|negative|ruled\s+out|"
    r"did\s+not|does\s+not|was\s+not|were\s+not)\b", re.IGNORECASE)


def _absence_shaped(text: str) -> bool:
    return bool(_NEGATION_RE.search(text or ""))


_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.;!?])\s+")

# Entity types whose rendering legitimately differs between a key and a
# finding (a local-time key against a UTC-normalised analyst), so a
# mismatch on them proves nothing about the subject.
_UNANCHORED_ENTITY_TYPES = frozenset({"ts"})

# A sentence credited on prose alone must state most of the key item (see
# _bundled_matches); a shared canonical entity needs no majority.
_SENTENCE_MAJORITY = 0.5


def _anchors_disagree(reference: str, text: str) -> bool:
    """True when both texts name concrete artifacts of a shared type and
    none coincide: a key item about one mailbox against a sentence about
    another mailbox is about a different subject, however many prose words
    the two share."""
    def anchors(s: str) -> set[str]:
        return {e for e in _entities.discriminative(_entities.extract(s))
                if e.split(":", 1)[0] not in _UNANCHORED_ENTITY_TYPES}
    a, b = anchors(reference), anchors(text)
    if not a or not b or (a & b):
        return False
    return bool({e.split(":", 1)[0] for e in a} & {e.split(":", 1)[0] for e in b})


def _bundled_matches(missed: list[dict], trace_findings: list[dict],
                     match_threshold: float) -> list[dict]:
    """Second pass over the key items the finding-level match left uncredited.

    A finding written as a narrative carries several key facts in one
    description; the primary pass hands each finding to one item and consumes
    it, so the finding's other facts score as misses. This pass matches the
    remaining items against sentences instead, each sentence consumable once.
    A run that records one fact per finding has nothing left to gain here,
    and precision is untouched: it stays finding-level, one credit per
    finding being enough.

    Three guards keep a sentence from crediting what the finding did not say.
    A negation-shaped sentence cannot satisfy a positive item (the absence
    of a payload is not the payload). A sentence whose concrete artifacts
    are all different from the item's names a different subject. And a
    prose-only match must cover the majority of the item's content words:
    the primary threshold was set for a one-line item against a whole
    paragraph, where a two-word overlap is diluted by everything else the
    paragraph says; a sentence is as short as the item, so two shared words
    are most of what it says, and this pass has no consumed-finding brake
    to stop a generic sentence from serving item after item.
    """
    units: list[tuple[int, str]] = []
    for i, tf in enumerate(trace_findings):
        for sentence in _SENTENCE_SPLIT_RE.split(tf.get("description", "")):
            if sentence.strip():
                units.append((i, sentence))
    spent: set[int] = set()
    out: list[dict] = []
    for gt_item in missed:
        ref = gt_item.get("description", "")
        ref_negative = _absence_shaped(ref)
        best_u, best_score, best_quality = -1, match_threshold, "none"
        for u, (_i, text) in enumerate(units):
            if u in spent:
                continue
            if (not ref_negative and _absence_shaped(text)) or _anchors_disagree(ref, text):
                continue
            score, quality = _match_detail(ref, text)
            if quality != "entity" and score < _SENTENCE_MAJORITY:
                continue
            if score > best_score:
                best_u, best_score, best_quality = u, score, quality
        if best_u == -1:
            continue
        spent.add(best_u)
        i, text = units[best_u]
        out.append({
            "ground_truth_id": gt_item.get("id", ""),
            "trace_call_id": trace_findings[i].get("call_id", 0),
            "sentence": text,
            "score": round(best_score, 3),
            "match_quality": best_quality,
        })
    return out


def _absence_match_score(assertion: str, finding: dict) -> float:
    """Score a negative assertion against one finding.

    UNCONFIRMED findings keep whole-description matching (the legacy
    convention: the whole entry IS the absence claim). For tiered findings
    the negation must live in the SAME SENTENCE as the token match —
    long multi-claim findings routinely end in an unrelated caveat ("…does
    not by itself prove X"), and whole-paragraph matching let that caveat
    qualify the entire finding as absence-shaped (a backfill:
    a CD-R carving finding satisfied the BadUSB negative assertion on the
    generic tokens 'device'+'present')."""
    desc = finding.get("description", "")
    if finding.get("confidence", "").upper() == "UNCONFIRMED":
        return _match_score(assertion, desc)
    best = 0.0
    for sentence in _SENTENCE_SPLIT_RE.split(desc):
        if _absence_shaped(sentence):
            best = max(best, _match_score(assertion, sentence))
    return best


def unscorable_reason(gt: dict) -> str | None:
    """Why this ground truth cannot be scored as findings, or None if it can.

    A CTF grader key (a top-level "flag", bare per-question hash/answer
    values, or a declared ``key_format``) carries none of the Atlas GT schema
    keys (`expected_findings` / `negative_assertions`). Scoring it would make
    every real finding a false positive and yield a meaningless precision=0 /
    recall=0 — a false 0% that reads to the reviewer as "disqualifying". A
    well-formed Atlas GT
    with an empty expected_findings list is NOT unscorable (it still scores
    negative-assertion coverage), so key on the schema keys being absent, not
    on emptiness. Callers must treat `unscorable` as "no accuracy available",
    never as 0%.

    Case authors can declare the key shape explicitly with a top-level
    ``key_format`` field (e.g. ``{"key_format": "md5-per-question"}``) —
    that beats the shape heuristic and is the recommended form.
    """
    if "expected_findings" in gt or "negative_assertions" in gt:
        return None
    if gt.get("key_format"):
        return (f"ground_truth declares key_format={gt['key_format']!r} — a "
                f"CTF answer key, not finding-shaped ground truth; accuracy "
                f"not computed (transcribe the answer key into "
                f"expected_findings to score this case)")
    looks_like_ctf_key = "flag" in gt or (bool(gt) and all(
        isinstance(v, str) and _looks_like_answer_hash(v)
        for k, v in gt.items() if k not in ("case_id", "flag")))
    return ("ground_truth carries no `expected_findings` or "
            "`negative_assertions`"
            + (" and looks like a CTF flag/hash answer key"
               if looks_like_ctf_key else "")
            + "; accuracy not computed (transcribe the answer key into "
              "finding-shaped expected_findings to score this case)")


def compare_findings(gt: dict, trace_findings: list[dict],
                     match_threshold: float = 0.30) -> dict:
    """Pure comparison of finding entries against a parsed ground truth.

    No file or execution-log access — the accuracy_compare tool feeds it the
    live trace; offline backfills (scorer regression, re-scoring of graded runs)
    feed it stored execution_log.json entries.
    """
    reason = unscorable_reason(gt)
    if reason is not None:
        return {"success": True, "unscorable": True, "reason": reason,
                "case_id": gt.get("case_id", ""), "summary": None}

    expected = gt.get("expected_findings", []) or []

    # Greedy matching: for each ground-truth item, take the highest-scoring
    # unmatched trace finding above threshold. This is deterministic and easy
    # to defend in the accuracy report.
    matched_trace_idxs: set[int] = set()
    true_positives = []
    false_negatives = []
    confidence_downgrades = []

    for gt_item in expected:
        best_idx = -1
        best_score = match_threshold  # must exceed threshold to count
        best_quality = "none"
        for i, tf in enumerate(trace_findings):
            if i in matched_trace_idxs:
                continue
            score, quality = _match_detail(
                gt_item.get("description", ""), tf.get("description", ""))
            if score > best_score:
                best_score = score
                best_idx = i
                best_quality = quality
        if best_idx == -1:
            false_negatives.append({
                "id": gt_item.get("id", ""),
                "description": gt_item.get("description", ""),
                "confidence_min": gt_item.get("confidence_min", ""),
            })
            continue
        matched_trace_idxs.add(best_idx)
        tf = trace_findings[best_idx]
        true_positives.append({
            "ground_truth_id": gt_item.get("id", ""),
            "trace_finding": tf.get("description", ""),
            "trace_call_id": tf.get("call_id", 0),
            "score": round(best_score, 3),
            "match_quality": best_quality,
        })
        actual = tf.get("confidence", "")
        expected_tier = gt_item.get("confidence_min", "")
        if expected_tier and not _meets_min_tier(actual, expected_tier):
            confidence_downgrades.append({
                "ground_truth_id": gt_item.get("id", ""),
                "expected_tier": expected_tier,
                "actual_tier": actual,
            })

    false_positives = [
        {"description": tf.get("description", ""),
         "confidence": tf.get("confidence", ""),
         "call_id": tf.get("call_id", 0)}
        for i, tf in enumerate(trace_findings)
        if i not in matched_trace_idxs
    ]

    # Facts the run did write down, inside a finding the 1:1 pass credited
    # to another item. Diagnostic only: precision, recall and f1 above keep
    # their finding-level meaning so stored numbers stay comparable.
    bundled = _bundled_matches(false_negatives, trace_findings, match_threshold)

    # Negative-assertion scoring: "supported" when an absence-claiming
    # finding addresses it — UNCONFIRMED by convention, or any tier whose
    # description is negation-shaped (see _absence_shaped).
    negative_assertions = gt.get("negative_assertions", []) or []
    absence_findings = [
        tf for tf in trace_findings
        if tf.get("confidence", "").upper() == "UNCONFIRMED"
        or _absence_shaped(tf.get("description", ""))
    ]
    negative_results = []
    for na in negative_assertions:
        best_score = match_threshold
        best_finding = None
        for uf in absence_findings:
            score = _absence_match_score(na, uf)
            if score > best_score:
                best_score = score
                best_finding = uf
        negative_results.append({
            "assertion": na,
            "addressed": best_finding is not None,
            "matched_call_id": best_finding.get("call_id", 0) if best_finding else 0,
            "matched_confidence": (best_finding.get("confidence", "")
                                   if best_finding else ""),
            "score": round(best_score, 3) if best_finding else 0.0,
        })

    tp = len(true_positives)
    fp = len(false_positives)
    fn = len(false_negatives)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    addressed = sum(1 for r in negative_results if r["addressed"])
    negative_coverage = (
        addressed / len(negative_results) if negative_results else 1.0
    )

    return {
        "success": True,
        "case_id": gt.get("case_id", ""),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "confidence_downgrades": confidence_downgrades,
        "negative_assertions": negative_results,
        "bundled": bundled,
        "summary": {
            "true_positive_count": tp,
            "false_positive_count": fp,
            "false_negative_count": fn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "bundled_count": len(bundled),
            "fact_recall": round((tp + len(bundled)) / (tp + fn), 3) if (tp + fn) else 0.0,
            "negative_assertion_total": len(negative_results),
            "negative_assertion_addressed": addressed,
            "negative_coverage": round(negative_coverage, 3),
            "matcher_version": MATCHER_VERSION,
        },
    }


@mcp.tool()
@output_safe
def accuracy_compare(ground_truth_path: str, match_threshold: float = 0.30) -> dict:
    """Compare current execution-log findings against a ground-truth manifest.

    ground_truth_path: JSON file matching the schema:
        {
          "case_id": "...",
          "expected_findings": [
            {"id": "F1", "description": "...", "confidence_min": "CONFIRMED",
             "category": "implant"},
            ...
          ],
          "negative_assertions": ["..."]
        }

    Returns:
      true_positives:        [{trace_finding, ground_truth_id, score}]
      false_positives:       [trace_finding]   (in trace, no GT match)
      false_negatives:       [{id, description, confidence_min}]  (in GT, no match)
      bundled:               [{ground_truth_id, trace_call_id, sentence, score}]
                             false negatives whose fact a sentence of a credited
                             finding states — written down, not credited 1:1
      confidence_downgrades: [{ground_truth_id, expected_tier, actual_tier}]
      summary: precision, recall, f1, true_positive_count, false_positive_count,
               false_negative_count, bundled_count, fact_recall
               ((TP + bundled) / key size; diagnostic, not a match metric).
    """
    if not os.path.exists(ground_truth_path):
        return {"success": False, "error": f"ground_truth not found: {ground_truth_path}"}

    try:
        with open(ground_truth_path) as f:
            gt = json.load(f)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        return {"success": False, "error": f"ground_truth read failed: {e}"}

    from core.execution_log import log
    trace_findings = [e for e in log._entries if e.get("type") == "finding"]
    return compare_findings(gt, trace_findings, match_threshold)


@mcp.tool()
@output_safe
def accuracy_export_report(ground_truth_path: str, output_path: str) -> dict:
    """Run accuracy_compare and write a Markdown report to output_path.

    output_path must be inside analysis/, exports/, or reports/.
    """
    cmp = accuracy_compare(ground_truth_path)
    if not cmp.get("success"):
        return cmp

    s = cmp["summary"]
    lines = [
        f"# Accuracy Report — {cmp.get('case_id', 'unknown')}",
        "",
        "## Summary",
        f"- True positives: **{s['true_positive_count']}**",
        f"- False positives: **{s['false_positive_count']}**",
        f"- False negatives: **{s['false_negative_count']}**",
        f"- Precision: **{s['precision']}**",
        f"- Recall: **{s['recall']}**",
        f"- F1: **{s['f1']}**",
        "",
        "## True Positives",
    ]
    for tp in cmp["true_positives"]:
        lines.append(
            f"- `{tp['ground_truth_id']}` ↔ call #{tp['trace_call_id']} (score "
            f"{tp['score']}): {tp['trace_finding']}"
        )
    lines.append("")
    lines.append("## False Negatives (expected, not found)")
    for fn in cmp["false_negatives"]:
        lines.append(f"- `{fn['id']}` (expected ≥{fn['confidence_min']}): {fn['description']}")
    lines.append("")
    lines.append("## False Positives (found, not in ground truth)")
    for fp in cmp["false_positives"]:
        lines.append(f"- call #{fp['call_id']} [{fp['confidence']}]: {fp['description']}")
    lines.append("")
    lines.append("## Confidence Downgrades")
    for cd in cmp["confidence_downgrades"]:
        lines.append(
            f"- `{cd['ground_truth_id']}`: expected {cd['expected_tier']}, "
            f"recorded as {cd['actual_tier']}"
        )

    try:
        with open(output_path, "w") as f:
            f.write("\n".join(lines) + "\n")
    except OSError as e:
        return {"success": False, "error": f"write failed: {e}"}
    return {
        "success": True,
        "output_path": output_path,
        "summary": cmp["summary"],
    }
