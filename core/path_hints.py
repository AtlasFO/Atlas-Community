"""Actionable path recovery hints for missing evidence inputs.

When an agent guesses a canonical KAPE/EZTools filename (``MFT.csv``) that
does not exist, the input-path gate must not only refuse — it must surface
sibling names and layout redirects so the next turn can open the real file.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

_HINT_LIMIT = 20

# Tokens that commonly appear in guessed vs real KAPE/EZTools basenames.
_TOKEN_RE = re.compile(
    r"(?i)(mft|usn|usnjrnl|evtx|amcache|shim|prefetch|regripper|"
    r"hayabusa|chainsaw|timeline|journal|security|system|software|sam)"
)

# Where a delivery puts a host's raw filesystem extract and its parser exports
# differs from one delivery to the next, so no tree name is assumed. What is
# universal: the folders the public parsers write into (Eric Zimmerman's
# tools, RegRipper, Hayabusa, chainsaw) and the folders only a raw Windows
# filesystem has.
_PARSERS = (r"MFTECmd|Evtxe?Cmd|RECmd|PECmd|LECmd|JLECmd|SBECmd|RBCmd|WxTCmd|"
            r"SQLECmd|SumECmd|SrumECmd|RLA|AmcacheParser|AppCompatCacheParser|"
            r"RegRipper|Hayabusa|Chainsaw")
# A parser's name as a whole path segment or as a token of one
# (MFTECmd/, MFTECmd_Output/, 2031-02_MFTECmd/), never inside a word.
_PARSER_SEGMENT = rf"(?:[^/]*[_\-. ])?(?:{_PARSERS})(?:[_\-. ][^/]*)?"
PARSER_DIR_RE = re.compile(rf"(?i)(?:^|/){_PARSER_SEGMENT}(?:/|$)")
RAW_FS_DIR_RE = re.compile(
    r"(?i)(?:^|/)(?:Windows/System32|Users/[^/]+/AppData|ProgramData|"
    r"\$Extend|winevt/Logs)(?:/|$)")
# Entries of a folder that is the root of a raw Windows filesystem extract.
_RAW_FS_ROOT_ENTRIES = frozenset({
    "$mft", "$extend", "$logfile", "$recycle.bin", "windows", "users",
    "programdata", "program files"})

_LAYOUT_REDIRECTS = (
    # (path fragment that signals the wrong kind of tree, hint)
    (
        re.compile(rf"(?i)(?:^|/)(?:Windows|Users|ProgramData|\$Extend)/(?:.+/)?{_PARSER_SEGMENT}(?:/|$)"),
        "Parser output folders do not sit inside a raw filesystem extract. "
        "List the evidence root (misc.list_evidence_dir) for the tree that "
        "holds this host's parser exports.",
    ),
    (
        re.compile(r"(?i)(?:^|/)(?:Windows|Users|ProgramData)/.+\.(?:csv|tsv|json|jsonl|xlsx)$"),
        "A raw filesystem extract holds $MFT, winevt logs and hives, not "
        "parser CSVs. Look for this host's parser exports (e.g. an MFTECmd/ "
        "folder) in a sibling tree of the evidence.",
    ),
    (
        re.compile(r"(?i)/AppCompatCache/"),
        "Windows Amcache hive lives under Windows/AppCompat/Programs/"
        "Amcache.hve (not AppCompatCache/). Prefer an already-parsed Amcache "
        "CSV (AmcacheParser output) when the evidence carries one.",
    ),
    (
        re.compile(rf"(?i)(?:^|/){_PARSER_SEGMENT}/(?:.+/)?(?:Windows|Users|\$MFT|\$Extend)(?:/|$)"),
        "Raw filesystem objects ($MFT, winevt, hives) do not sit inside a "
        "parser output folder; they are in the host's raw extract.",
    ),
)


# NTFS metadata files: a folder holding one is a raw filesystem extract.
_NTFS_METADATA_FILES = frozenset({
    "$mft", "$mftmirr", "$logfile", "$volume", "$attrdef", "$bitmap",
    "$boot", "$badclus", "$secure", "$upcase", "$extend"})


def looks_like_raw_fs_root(names) -> bool:
    """Whether a folder holding ``names`` is the root of a raw Windows
    filesystem extract: it holds an NTFS metadata file, or two or more of
    its entries are ones only such a root has."""
    folded = {n.casefold() for n in names}
    return bool(folded & _NTFS_METADATA_FILES) or len(folded & _RAW_FS_ROOT_ENTRIES) >= 2


def _fuzzy_score(guessed: str, candidate: str) -> int:
    g = guessed.casefold()
    c = candidate.casefold()
    score = 0
    if g == c:
        return 100
    g_stem = Path(g).stem
    c_stem = Path(c).stem
    if g_stem and g_stem in c:
        score += 40
    for tok in _TOKEN_RE.findall(g):
        if tok.casefold() in c:
            score += 15
    # Shared prefix length (cheap)
    for a, b in zip(g_stem, c_stem):
        if a != b:
            break
        score += 1
    return score


def list_siblings(parent: str, *, limit: int = _HINT_LIMIT) -> list[str]:
    """Return up to ``limit`` basenames in an existing directory."""
    try:
        names = sorted(
            n for n in os.listdir(parent)
            if not n.startswith(".")
        )
    except OSError:
        return []
    return names[:limit]


def format_missing_path_hint(missing_path: str) -> str:
    """Build a recovery hint for one nonexistent input path."""
    path = os.path.expanduser(missing_path.strip())
    parts: list[str] = []
    parent = os.path.dirname(path)
    guessed = os.path.basename(path)

    if parent and os.path.isdir(parent):
        try:
            all_names = [
                n for n in os.listdir(parent) if not n.startswith(".")
            ]
        except OSError:
            all_names = []
        ranked = sorted(
            all_names,
            key=lambda n: _fuzzy_score(guessed, n),
            reverse=True,
        )
        fuzzy = [n for n in ranked if _fuzzy_score(guessed, n) >= 15][:8]
        siblings = ranked[:_HINT_LIMIT]
        if fuzzy:
            parts.append(
                f"Parent exists ({parent}). Close basename matches: "
                + ", ".join(fuzzy)
            )
        elif siblings:
            parts.append(
                f"Parent exists ({parent}). Siblings: "
                + ", ".join(siblings)
            )
        else:
            parts.append(f"Parent exists but is empty: {parent}")
        parts.append(
            "List the directory (misc.list_evidence_dir) before guessing "
            "canonical names like MFT.csv / USNJRNL.csv."
        )
        if (Path(guessed).suffix.casefold() in (".csv", ".tsv", ".json", ".jsonl", ".xlsx")
                and looks_like_raw_fs_root(all_names)):
            parts.append(
                f"{parent} is a raw filesystem extract ($MFT, Windows/, "
                "Users/): parser exports such as MFT.csv are not written "
                "there. Look for the same host's folder in a sibling tree "
                "of the evidence, or parse the raw file (ez.ez_mftecmd on "
                "the $MFT)."
            )
    else:
        # Parent missing — climb for nearest existing ancestor
        climb = parent
        found = None
        while climb and climb not in ("/", ""):
            if os.path.isdir(climb):
                found = climb
                break
            climb = os.path.dirname(climb)
        if found:
            sibs = list_siblings(found, limit=12)
            parts.append(
                f"No such path; nearest existing directory: {found}"
                + (f" (contains: {', '.join(sibs)})" if sibs else "")
            )
        else:
            parts.append("Path and parent do not exist.")

    # Layout hints are about the evidence tree. Above it, a home folder
    # named Users (macOS, a WSL mount of C:) says nothing, so only the part
    # below the last evidence/ folder is read.
    below = ("/" + path.replace("\\", "/").lstrip("/")).rpartition("/evidence/")
    if below[1]:
        for rx, hint in _LAYOUT_REDIRECTS:
            if rx.search("/" + below[2]):
                parts.append(hint)
                break

    return " ".join(parts)


def enrich_missing_paths_message(missing_specs: list[str]) -> str:
    """Append hints for middleware ToolError body.

    ``missing_specs`` entries look like ``path='/abs/…/MFT.csv'``.
    """
    hints: list[str] = []
    for spec in missing_specs:
        # key='path' form or raw path
        m = re.search(r"='([^']+)'|=\"([^\"]+)\"|=([^,\s]+)$", spec)
        raw = (m.group(1) or m.group(2) or m.group(3)) if m else ""
        if not raw:
            # fall back: after first =
            if "=" in spec:
                raw = spec.split("=", 1)[1].strip().strip("'\"")
        if raw:
            hints.append(format_missing_path_hint(raw))
    if not hints:
        return (
            " Pass a real evidence/analysis path; empty success on a "
            "missing path is not allowed. Call misc.list_evidence_dir on "
            "the parent folder instead of inventing basenames."
        )
    # Dedupe while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for h in hints:
        if h not in seen:
            seen.add(h)
            unique.append(h)
    body = " | ".join(unique)
    return (
        ". Pass a real evidence/analysis path; empty success on a missing "
        f"path is not allowed. Recovery: {body}"
    )
