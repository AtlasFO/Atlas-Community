"""Gate: the calls a finding cites must be about the evidence it describes.

``lineage_required`` proves every cited call_id exists. This gate asks the
next question: does the cited work concern the artifacts the finding names?
A finding about a document carved from a disk image that cites only packet
searches over a capture carries a valid-looking citation and no support —
and because the hash chain and the id check both hold, nothing downstream
notices. A meaningless link is worse than a missing one: it survives review.

The judgement is made on concrete artifact references only, never on prose:
the file and path names in the description (and supporting evidence)
against those in the cited calls' commands, evidence references, arguments
and result excerpts, via ``core.entities.artifact_tokens``. It refuses only
when both sides name artifacts and share none. A finding without a concrete
path, or a cited reason/correlate call that names none, is left alone —
there is nothing to compare, and an unjustified refusal blocks real work.

Lineage that Atlas inferred (the agent omitted ``input_call_ids``) is never
refused here: the agent did not choose those citations, so relevance is
enforced where they are chosen — ``tools.misc._infer_input_call_ids`` prefers
recent calls that name the finding's artifacts.

``ATLAS_LINEAGE_RELEVANCE=0`` disables the gate.
"""
from __future__ import annotations

import os
from typing import Optional

from core.entities import artifact_tokens

# How much of a cited call's spilled output is read for the artifacts it
# names. Only cited calls are read this way; a scan over the trace's recent
# past for lineage inference keeps to the excerpt.
SPILL_HEAD_CHARS = 200_000


# A command names what ran, not always what it was about: a wrapper may
# hand the tool a staged alias, or a typed tool's subprocess may name only
# a working copy. The evidence reference and arguments the trace stamped on
# the call say what the analyst asked for, so relevance is judged on those
# too.
def entry_text(entry: dict, *, include_file: bool = False) -> str:
    """What a call was asked to read and what it returned. With
    ``include_file`` the head of the output kept on disk is read too: a
    parser run over a directory lists the artifacts it read in its output,
    and a long listing carries most of them past the trace excerpt."""
    parts = [str(entry.get(k) or "")
             for k in ("cmd", "evidence_ref", "args", "stdout_excerpt")]
    sf = entry.get("stdout_file") if include_file else None
    if sf:
        try:
            with open(str(sf), encoding="utf-8", errors="replace") as fh:
                parts.append(fh.read(SPILL_HEAD_CHARS))
        except OSError:
            pass
    return " ".join(parts)


def check(ctx) -> Optional[dict]:
    if os.environ.get("ATLAS_LINEAGE_RELEVANCE", "1").strip() == "0":
        return None
    if getattr(ctx, "lineage_inferred", False):
        return None

    described = artifact_tokens(
        f"{ctx.description or ''} {ctx.supporting_evidence or ''}")
    if not described:
        return None

    cids = list(getattr(ctx, "input_call_ids", None) or [])
    linked = getattr(ctx, "linked_call_id", 0)
    if linked and linked not in cids:
        cids.append(linked)
    by_call_id = getattr(getattr(ctx, "idx", None), "by_call_id", None) or {}

    cited: set[str] = set()
    cited_calls: list[tuple[int, str]] = []
    for cid in cids:
        entry = by_call_id.get(cid) or {}
        if entry.get("type") != "tool_call":
            continue
        tokens = artifact_tokens(entry_text(entry, include_file=True))
        if tokens:
            cited |= tokens
            cited_calls.append((int(cid), str(entry.get("cmd") or "")[:80]))
    if not cited:
        return None
    if described & cited:
        return None

    return {
        "success": False,
        "error": (
            "The cited calls are not about the artifacts this finding "
            f"describes. Finding names {sorted(described)[:6]}; the cited "
            "calls name "
            + "; ".join(f"call {cid}: {cmd}" for cid, cmd in cited_calls[:4])
            + ". Cite the call that read or produced the described artifact "
            "(its _atlas_call_id), or drop the unrelated ids — or omit "
            "input_call_ids and let Atlas infer lineage from the calls that "
            "touched these artifacts."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "lineage_relevance",
        "described_artifacts": sorted(described),
        "cited_artifacts": sorted(cited),
    }
