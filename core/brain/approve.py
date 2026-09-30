"""Promote an approved memory candidate into durable memory.

The only supported path from staged candidate to memory/, wiki/, or logs/.
"""

from __future__ import annotations

import argparse
import datetime as dt
import shutil
from pathlib import Path

from core.brain import (answer_key, contributors, environment, frontmatter,
                        identifiers, indexes, secrets, store)


class ApproveError(Exception):
    pass


# The only brain trees published to the public GitHub remote. A note promoted
# here must be generalized — no raw case identifiers/IOCs/PII. wiki/cases
# (internal case pages) and wiki/environments (client baselines) are exempt:
# they stay on the private remote and legitimately carry client infra.
_PUBLIC_WIKI_DIRS = ("wiki/concepts", "wiki/techniques", "wiki/tools",
                     "wiki/actors")


def _is_public_wiki_destination(destination: str) -> bool:
    d = destination.strip().lstrip("/")
    return any(d == p or d.startswith(p + "/") for p in _PUBLIC_WIKI_DIRS)


def _extract_section(body: str, heading: str) -> str:
    lines, capture = [], False
    for line in body.splitlines():
        if line.startswith("#"):
            capture = heading.lower() in line.lower()
            continue
        if capture:
            lines.append(line)
    return "\n".join(lines).strip()


def approve(candidate: Path, yes: bool = False) -> Path:
    root = store.brain_root()
    # Contributor gate: durable brain growth is limited to the CONTRIBUTORS
    # allow-list. No-op while brain/CONTRIBUTORS is absent (single-user/dev).
    if not contributors.is_contributor():
        ident = contributors.current_identity() or "<unknown git identity>"
        raise ApproveError(
            f"refusing approval: {ident} is not in brain/CONTRIBUTORS — durable "
            "brain growth is limited to contributors. Propose it via a branch + "
            "merge request, or ask a maintainer to approve and merge it.")
    candidate = candidate if candidate.is_absolute() else root / candidate
    if not candidate.is_file():
        raise ApproveError(f"candidate not found: {candidate}")
    text = candidate.read_text(encoding="utf-8", errors="replace")
    meta, body, _ = frontmatter.parse(text)

    hits = secrets.scan_text(text)
    if hits:
        kinds = ", ".join(sorted({h.pattern for h in hits}))
        raise ApproveError(
            f"refusing approval: secret-like content detected ({kinds}) — "
            "edit the candidate first")
    if (meta.get("risk") or {}).get("contains_sensitive_data"):
        raise ApproveError(
            "refusing approval: candidate is flagged contains_sensitive_data "
            "— review and edit it, then clear the flag")
    # Answer-key leak guard — a hard block, never clearable by a flag edit.
    # Two layers: the marker capture stamps when it scrubbed a ground-truth
    # secret, plus an independent re-scan of the raw text against the case's
    # ground truth so a hand-authored or pre-guard candidate that quotes the
    # answer with no marker is caught too.
    if (meta.get("risk") or {}).get("contains_answer_key"):
        raise ApproveError(
            "refusing approval: candidate is flagged contains_answer_key — it "
            "quotes training ground-truth material and must never enter "
            "analyst-injectable memory")
    case_id = str((meta.get("origin") or {}).get("case_id") or "")
    if answer_key.scan(text, answer_key.secrets_for_case_id(case_id)):
        raise ApproveError(
            "refusing approval: candidate quotes this case's ground-truth "
            "answer key verbatim — it must never enter analyst-injectable "
            "memory")

    destination = str(meta.get("suggested_destination") or "").strip()
    if not destination:
        raise ApproveError("candidate has no suggested_destination")
    dest = (root / destination).resolve()
    if root.resolve() not in dest.parents:
        raise ApproveError(f"destination escapes the brain: {destination}")

    # Environment baseline guard — a hard block like the answer-key one, no
    # override: baselines never need verdict vocabulary (describe the
    # behavior, not the judgment), and run-derived provenance is a prior
    # solve wearing a disguise.
    if environment.is_environment_destination(destination):
        problems = environment.validate(meta, text)
        if problems:
            raise ApproveError(
                "refusing approval into wiki/environments/: "
                + "; ".join(problems)
                + " — environment notes are client-provided baselines only: "
                "no agent-run provenance, no verdicts, no prior-incident "
                "indicators. Old IOCs belong in the per-case wiki entry, "
                "not the environment baseline.")

    # Public-boundary gate — wiki/{concepts,techniques,tools,actors} is the only
    # brain content that reaches the public GitHub remote, so a note promoted
    # there must be GENERALIZED. Hard block, no flag override (same posture as
    # the answer-key guard). Two layers: raw identifiers/IOCs/PII, and the
    # existing case-specific to-do heuristic.
    if _is_public_wiki_destination(destination):
        id_hits = identifiers.scan_text(text)
        if id_hits:
            kinds = ", ".join(sorted({h.kind for h in id_hits}))
            raise ApproveError(
                f"refusing approval into {destination}: case-specific "
                f"identifier(s) detected ({kinds}) — the public wiki must be "
                "generalized. Redact IOCs/hosts/accounts/e-mails to "
                "placeholders (see `atlas brain approve --show-redacted`) and "
                "re-approve.")
        from core.brain.capture import _review_hints
        if _review_hints(text)["likely_case_specific"]:
            raise ApproveError(
                f"refusing approval into {destination}: content looks "
                "case-specific (to-do / logistics signals) — a wiki note must "
                "be a generalized, reusable lesson, not a case action item. "
                "Rewrite it and re-approve.")

    proposed = _extract_section(body, "Proposed Entry") or body.strip()
    now = dt.datetime.now(dt.timezone.utc)
    date = now.date().isoformat()
    timestamp = now.strftime("%Y-%m-%d %H:%M UTC")
    entry = (f"\n## From {candidate.name} ({date})\n\n{proposed}\n")

    if dest.suffix != ".md":  # a directory: create a note in it
        dest.mkdir(parents=True, exist_ok=True)
        title = str(meta.get("title", candidate.stem))
        dest = dest / f"{store.slugify(title)}.md"

    if not yes:
        print(f"Will append the proposed entry to: {dest}")
        answer = input("Approve? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            raise ApproveError("aborted")

    if dest.exists():
        dest.write_text(dest.read_text(encoding="utf-8").rstrip() + "\n" + entry,
                        encoding="utf-8")
    else:
        new_meta = {
            "title": str(meta.get("title", candidate.stem)),
            "type": _type_for_destination(destination),
            # Keep the candidate's creation time and run attribution so the
            # globe's growth replay places the note in the run that earned it.
            "created": str(meta.get("created") or timestamp),
            "updated": timestamp,
            "status": "active",
            "source_classification": meta.get("source_classification",
                                              "internal"),
            "confidence": meta.get("confidence", "medium"),
            "knowledge_kind": meta.get("knowledge_kind") or "",
            "tags": [t for t in (meta.get("tags") or []) if t != "agent-run"],
            "related": [],
            "source": meta.get("source") or {"type": "agent_run"},
            "origin": meta.get("origin") or {},
            "entities": meta.get("entities") or {},
        }
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(frontmatter.serialize(new_meta, entry.strip() + "\n"),
                        encoding="utf-8")

    meta["status"] = "processed"
    meta["updated"] = date
    processed = root / "inbox/processed" / candidate.name
    processed.write_text(frontmatter.serialize(meta, body), encoding="utf-8")
    candidate.unlink()
    indexes.rebuild()
    return dest


def _type_for_destination(destination: str) -> str:
    for note_type, d in store.TYPE_DIRS.items():
        if destination.rstrip("/").startswith(d) or destination.startswith(d):
            return note_type
    return "note"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Promote a memory candidate into durable memory")
    parser.add_argument("candidate")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument(
        "--show-redacted", action="store_true",
        help="preview the candidate with case-specific identifiers redacted, "
             "then exit without promoting")
    args = parser.parse_args(argv)
    if args.show_redacted:
        cand = Path(args.candidate)
        cand = cand if cand.is_absolute() else store.brain_root() / cand
        if not cand.is_file():
            print(f"error: candidate not found: {cand}")
            return 1
        redacted, hits = identifiers.redact(
            cand.read_text(encoding="utf-8", errors="replace"))
        if hits:
            kinds = ", ".join(sorted({h.kind for h in hits}))
            print(f"# {len(hits)} identifier hit(s) ({kinds}) — "
                  "generalized preview below:\n")
        else:
            print("# no case-specific identifiers detected\n")
        print(redacted)
        return 0
    try:
        dest = approve(Path(args.candidate), yes=args.yes)
    except ApproveError as e:
        print(f"error: {e}")
        return 1
    print(f"Approved -> {dest}")
    print("Indexes rebuilt.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
