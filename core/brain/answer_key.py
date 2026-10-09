"""Answer-key leak guard for brain candidate capture.

Training cases ship a ``ground_truth.json`` (the answer key) next to the
evidence. The analyst is blocked from ever reading it (see the solution
blocklist in ``core.paths``), but findings and reviewer recommendations
mined into memory candidates can still quote a *recovered* secret verbatim
— an AES key, a flag value, a credential, the name of the payload file —
and a careless ``atlas brain approve`` would then promote that secret into
analyst-injectable memory, leaking the answer on the next run of the same
case. On a case whose answer is a recovered key, candidates embed it
verbatim run after run: a credential assignment such as
``user01=Example-2031!``, or the payload's file name such as ``secret.bin``.

This module reads the ground truth SERVER-SIDE ONLY, to scrub candidates
before they are staged and to hard-block approval. It must never surface
ground-truth content on any analyst-facing path — the extracted secrets
exist only to be redacted out of / matched against candidate text.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

# Ground truth lives at one of these spots depending on the case (the repo is
# inconsistent: accuracy reads evidence/, review reads root + analysis/). Look
# in every known location so no case slips the guard.
_GT_LOCATIONS = ("ground_truth.json",
                 "evidence/ground_truth.json",
                 "analysis/ground_truth.json")

# Top-level keys a case author can use to declare answer-key secrets verbatim
# (values that are not secret-*shaped* — filenames, plaintext passphrases —
# and so must be listed explicitly rather than mined). Each may hold a list of
# strings, or of dicts carrying a "value"/"secret" field.
_EXPLICIT_SECRET_KEYS = ("secrets", "answer_key", "answer_keys", "flags",
                         "known_values", "sensitive_values")

# Shortest explicit secret we will scan for — below this the risk of nuking a
# common word out of every candidate outweighs the leak it would prevent.
_MIN_EXPLICIT_LEN = 5

# Secret-*shaped* tokens mined from arbitrary ground-truth strings (finding
# descriptions, negative assertions). Kept strict so descriptive prose
# ("Windows 7 Ultimate", "RID 1000") is never mistaken for an answer.
_MINE_PATTERNS = (
    # flag{...} / ctf{...} / htb{...} / key{...}
    re.compile(r"(?i)\b(?:flag|ctf|htb|thm|key)\{[^}]{2,}\}"),
    # credential assignment: user01=Example-2031!, password=hunter2
    re.compile(r"\b[A-Za-z_][\w.-]*=[^\s\"',;)]{4,}"),
    # hashes / long hex serials
    re.compile(r"\b[0-9a-fA-F]{16,}\b"),
    # base64-ish / long opaque tokens
    re.compile(r"\b[A-Za-z0-9+/_-]{24,}={0,2}\b"),
)

REDACTION = "[REDACTED:answer_key]"


def _find_ground_truth(case_dir: Path) -> Path | None:
    for rel in _GT_LOCATIONS:
        p = case_dir / rel
        try:
            if p.is_file():
                return p
        except OSError:
            # A directory the process cannot stat — `lost+found` on the
            # cases volume is root-owned on every ext4 filesystem. Scanning
            # for a ground truth must not take brain editing and the
            # dashboard's review down with it.
            continue
    return None


# Top-level folders of a case the search for copies of a key does not enter:
# the evidence tree (its own top level is searched), opened images' mount
# points and raw exports. A copy in them is still refused by its name
# (core.paths.is_solution_path), only not stashed.
_UNSEARCHED_DIRS = frozenset({"evidence", "mnt", "exports"})
# How far the search for copies of a key goes below each top-level folder of
# the case, level by level: an operator's or a grader's copy sits near the
# top, parser and extraction output (thousands of files) lies deeper, and a
# large folder never delays a shallow sibling.
# ponytail: a copy deeper than _KEY_SEARCH_DEPTH levels, or in a folder the
# remaining entry budget cannot list (that folder is skipped, its siblings are
# still searched; the deepest levels run out first), stays unstashed and
# unregistered (still refused by its name); a name index of the output trees
# when keys turn up that deep.
_KEY_SEARCH_DEPTH = 4
_KEY_SEARCH_ENTRIES = 100_000


def _shallow_files(top: Path):
    """Files at most _KEY_SEARCH_DEPTH levels below ``top``, breadth-first
    and at most _KEY_SEARCH_ENTRIES entries in all (a folder larger than what
    is left is skipped), without following a link or entering an opened
    image's mount point."""
    from core.evidence_catalog import _opened_image_mount

    level, budget = [top], _KEY_SEARCH_ENTRIES
    for _ in range(_KEY_SEARCH_DEPTH):
        deeper: list[Path] = []
        for folder in level:
            try:
                with os.scandir(folder) as it:
                    entries = sorted(it, key=lambda e: e.name)
            except OSError:
                continue
            if len(entries) > budget:
                continue                # too large to list: its siblings still are
            budget -= len(entries)
            for e in entries:
                try:
                    if e.is_symlink():
                        continue
                    if e.is_file():
                        yield Path(e.path)
                    elif e.is_dir() and not _opened_image_mount(e.path):
                        deeper.append(Path(e.path))
                except OSError:
                    continue
        level = deeper


def answer_key_paths(case_dir) -> list[Path]:
    """Every answer-key file the framework recognises for ``case_dir``: the
    known ground-truth locations, in their order, then every other file in
    the case whose name is an answer key's (``core.paths.is_answer_key_name``):
    a copy under .atlas/ or analysis/, a ground_truth.<lang>.json.

    Feeds the positive-identifier gate (``core.paths.register_answer_keys``)
    and the filesystem stash: whatever the framework treats as a grading key
    is what must be blocked / hidden from the analyst. Which key grades stays
    the first known location (``_find_ground_truth``). Best-effort, never
    raises — a bad case_dir simply yields no keys.
    """
    out: list[Path] = []
    try:
        base = Path(case_dir)
    except (TypeError, ValueError):
        return out
    seen: set[str] = set()

    def add(p: Path) -> None:
        if str(p) not in seen:
            seen.add(str(p))
            out.append(p)

    for rel in _GT_LOCATIONS:
        try:
            p = base / rel
            if p.is_file():
                add(p)
        except OSError:
            continue
    from core.paths import is_answer_key_name

    def copy(p: Path) -> bool:
        # A link is followed by the realpath gate; moving its target could
        # take a file from outside the case.
        return is_answer_key_name(p.name) and p.is_file() and not p.is_symlink()

    try:
        top = sorted(base.iterdir())
    except OSError:
        return out
    for entry in top:
        try:
            if entry.name == "evidence" and entry.is_dir():
                # Evidence is often attached by a link; its top level is
                # read through it, nothing below.
                for p in sorted(entry.iterdir()):
                    if copy(p):
                        add(p)
            elif entry.is_symlink():
                continue
            elif entry.is_file():
                if copy(entry):
                    add(entry)
            elif entry.is_dir() and entry.name not in _UNSEARCHED_DIRS:
                for p in _shallow_files(entry):
                    if copy(p):
                        add(p)
        except OSError:
            continue
    return out


def has_ground_truth(case_dir: Path) -> bool:
    """True when the case ships a grading key — such a case is a training
    case, and client-scoped knowledge (Tier D) must stay out of its prompt."""
    return _find_ground_truth(Path(case_dir)) is not None


def _load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _iter_strings(value) -> list[str]:
    """Every string reachable inside a JSON-ish value (recursive)."""
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            out.extend(_iter_strings(v))
    elif isinstance(value, (list, tuple)):
        for v in value:
            out.extend(_iter_strings(v))
    return out


def _explicit_secrets(gt: dict) -> set[str]:
    found: set[str] = set()
    for key in _EXPLICIT_SECRET_KEYS:
        entries = gt.get(key)
        if not isinstance(entries, (list, tuple)):
            continue
        for entry in entries:
            if isinstance(entry, str):
                val = entry
            elif isinstance(entry, dict):
                val = entry.get("value") or entry.get("secret") or ""
            else:
                val = ""
            val = str(val).strip()
            if len(val) >= _MIN_EXPLICIT_LEN:
                found.add(val)
    return found


def _mined_secrets(gt: dict) -> set[str]:
    # Never mine the explicit-secret containers twice, and skip the case_id /
    # provenance blurbs — everything else (findings, assertions) is fair game.
    scope = {k: v for k, v in gt.items()
             if k not in _EXPLICIT_SECRET_KEYS
             and k not in ("case_id", "_comment", "_provenance")}
    found: set[str] = set()
    for s in _iter_strings(scope):
        for pat in _MINE_PATTERNS:
            found.update(m.group(0) for m in pat.finditer(s))
    return found


def extract_secrets(gt: dict) -> list[str]:
    """All answer-key secrets in a parsed ground_truth dict, longest first.

    Longest-first so that when one secret contains another as a substring
    the larger span is redacted before the smaller one can fragment it.
    """
    secrets = _explicit_secrets(gt) | _mined_secrets(gt)
    return sorted((s for s in secrets if s), key=len, reverse=True)


def load_secrets(case_dir: Path) -> list[str]:
    """Answer-key secrets for a case, or [] when it ships no ground truth.

    Best-effort and never raises: a missing or malformed ground_truth.json
    simply means no extra scrubbing, never a failed capture.
    """
    gt_path = _find_ground_truth(Path(case_dir))
    if gt_path is None:
        return []
    return extract_secrets(_load_json(gt_path))


def scan(text: str, secrets: list[str]) -> list[str]:
    """Which answer-key secrets appear (case-insensitively) in ``text``."""
    if not text or not secrets:
        return []
    return [s for s in secrets if re.search(re.escape(s), text, re.IGNORECASE)]


def redact(text: str, secrets: list[str]) -> tuple[str, list[str]]:
    """Replace every answer-key secret span with ``[REDACTED:answer_key]``.

    Returns ``(clean_text, matched_secrets)``. ``secrets`` is assumed
    longest-first (as ``extract_secrets`` / ``load_secrets`` return it) so
    overlapping secrets collapse to a single marker cleanly.
    """
    if not text or not secrets:
        return text, []
    matched: list[str] = []
    for s in secrets:
        new = re.sub(re.escape(s), REDACTION, text, flags=re.IGNORECASE)
        if new != text:
            matched.append(s)
            text = new
    return text, matched


# ── approve-side defense in depth ──────────────────────────────────────────
# capture stamps risk.contains_answer_key on candidates it scrubs, but a
# hand-authored or pre-guard candidate may quote a secret with no marker.
# approve re-derives the case's secrets from origin.case_id and re-scans.


def _cases_root() -> Path:
    from core.brain import store
    override = os.environ.get("ATLAS_CASES_ROOT")
    return Path(override) if override else store.REPO_ROOT / "cases"


def secrets_for_case_id(case_id: str) -> list[str]:
    """Answer-key secrets for the case whose ground_truth declares ``case_id``.

    Scans the cases root (``ATLAS_CASES_ROOT`` or ``<repo>/cases``) for a
    ground_truth.json whose ``case_id`` matches, case-insensitively; also
    matches the case directory name. Best-effort, never raises."""
    if not case_id:
        return []
    want = str(case_id).strip().lower()
    root = _cases_root()
    try:
        case_dirs = [d for d in root.iterdir() if d.is_dir()]
    except OSError:
        return []
    for case_dir in case_dirs:
        gt_path = _find_ground_truth(case_dir)
        if gt_path is None:
            continue
        gt = _load_json(gt_path)
        declared = str(gt.get("case_id", "")).strip().lower()
        if want in (declared, case_dir.name.lower()):
            return extract_secrets(gt)
    return []
