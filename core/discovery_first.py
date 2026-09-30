"""Discovery-first filesystem access — global agent architecture rule.

Principle
---------
**Authoritative discovery always overrides LLM assumptions.**

The LLM may reason about *evidence content*. It must not invent filenames,
directory layouts, parser export names, mount paths, or analysis paths when
inventory / listing / catalog can establish the answer.

This module is tool-agnostic (KAPE, EvtxECmd, mounts, CSV, SQLite, …). It
reuses Evidence Inventory, catalog samples, ``already_processed``, and
``list_evidence_dir`` — it does not introduce a parallel discovery system.

Flow (middleware)
-----------------
Need path → known? → use it
         → missing → try resolve via knowledge / inventory / unique sibling
         → resolved → rewrite args once, remember, continue
         → else refuse as ``gate: discovery_first`` (TOOL INFO) with discovery
           next step; identical guess never retried as a forensic tool call.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Optional

from core.envfile import env_int
from core.path_hints import (PARSER_DIR_RE, RAW_FS_DIR_RE, _fuzzy_score,
                             format_missing_path_hint, looks_like_raw_fs_root)

SCHEMA_VERSION = "1.0"

# Tools that *are* discovery — they may probe paths; still refuse inventing
# missing files inside them when applicable, but they are the recovery path.
DISCOVERY_TOOL_RE = re.compile(
    r"(?:list_evidence_dir|inventory_evidence|inventory_|catalog|"
    r"ensure_evidence|mount_plan|evidence_profile|mark_blocked|ledger_status|"
    r"resolve_path)",
    re.IGNORECASE,
)

_AUTO_RESOLVE_MIN_SCORE = env_int("ATLAS_DISCOVERY_AUTO_SCORE", 40)
# Clear winner margin when multiple inventory/sibling hits exist.
_AUTO_RESOLVE_MARGIN = env_int("ATLAS_DISCOVERY_AUTO_MARGIN", 15)

_TABULAR_EXTS = {".csv", ".tsv", ".json", ".jsonl", ".xlsx", ".txt"}
_RAW_NTFS_META_RE = re.compile(
    r"(?i)^(?:\$MFT(?:Mirr)?|\$LogFile|\$Boot|\$Bitmap|\$Secure.*|\$Extend|"
    r"\$UpCase|\$AttrDef|\$Volume)$"
)
# A flat VMDK image name or a hostname-shaped token (letters, then digits:
# WS05, FILE01, DC-02) that both a guessed and a candidate path can carry.
_HOST_TOKEN_RE = re.compile(
    r"(?i)([A-Za-z0-9_-]+-flat\.vmdk|(?<![A-Za-z0-9])[A-Za-z][A-Za-z0-9-]{2,20}\d{1,3}(?![A-Za-z0-9]))"
)


def knowledge_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "path_knowledge.json"


def empty_knowledge() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "updated_at": "",
        "known_paths": {},       # normalized_guess -> resolved_path
        "failed_guesses": {},    # normalized_path -> {count, last_at, hint}
        "discovered_dirs": {},   # dir -> {listed_at, sample_names[]}
    }


def load_knowledge(case_dir: str | os.PathLike | None) -> dict[str, Any]:
    if not case_dir:
        return empty_knowledge()
    path = knowledge_path(case_dir)
    if not path.is_file():
        return empty_knowledge()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty_knowledge()
    if not isinstance(data, dict):
        return empty_knowledge()
    out = empty_knowledge()
    out.update(data)
    out.setdefault("known_paths", {})
    out.setdefault("failed_guesses", {})
    out.setdefault("discovered_dirs", {})
    return out


def save_knowledge(case_dir: str | os.PathLike, knowledge: dict[str, Any]) -> None:
    path = knowledge_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    knowledge = dict(knowledge)
    knowledge["schema_version"] = SCHEMA_VERSION
    knowledge["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(knowledge, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp, path)


def _norm(path: str) -> str:
    return os.path.normpath(os.path.expanduser((path or "").strip()))


def remember_known_path(
    case_dir: str | os.PathLike | None,
    guessed: str,
    resolved: str,
    *,
    source: str = "discovery",
) -> None:
    if not case_dir or not resolved:
        return
    if not _compatible_candidate(guessed, resolved):
        return
    try:
        kn = load_knowledge(case_dir)
        kn.setdefault("known_paths", {})[_norm(guessed)] = {
            "resolved": _norm(resolved),
            "source": source,
            "at": time.time(),
        }
        # Also index by resolved as known-good
        kn["known_paths"][_norm(resolved)] = {
            "resolved": _norm(resolved),
            "source": source,
            "at": time.time(),
        }
        # Clear failure record for this guess
        kn.get("failed_guesses", {}).pop(_norm(guessed), None)
        save_knowledge(case_dir, kn)
    except OSError:
        pass


def remember_failed_guess(
    case_dir: str | os.PathLike | None,
    path: str,
    *,
    hint: str = "",
) -> int:
    """Record a failed invented path. Returns failure count for this path."""
    if not case_dir or not path:
        return 0
    try:
        kn = load_knowledge(case_dir)
        key = _norm(path)
        prev = (kn.get("failed_guesses") or {}).get(key) or {}
        count = int(prev.get("count") or 0) + 1
        kn.setdefault("failed_guesses", {})[key] = {
            "count": count,
            "last_at": time.time(),
            "hint": (hint or prev.get("hint") or "")[:500],
        }
        save_knowledge(case_dir, kn)
        return count
    except OSError:
        return 1


def failed_guess_count(case_dir: str | os.PathLike | None, path: str) -> int:
    if not case_dir:
        return 0
    kn = load_knowledge(case_dir)
    hit = (kn.get("failed_guesses") or {}).get(_norm(path)) or {}
    return int(hit.get("count") or 0)


def is_failed_guess(case_dir: str | os.PathLike | None, path: str) -> bool:
    return failed_guess_count(case_dir, path) > 0


def lookup_known(case_dir: str | os.PathLike | None, path: str) -> str | None:
    if not case_dir or not path:
        return None
    kn = load_knowledge(case_dir)
    hit = (kn.get("known_paths") or {}).get(_norm(path))
    resolved: str | None = None
    if isinstance(hit, dict):
        resolved = hit.get("resolved")
    elif isinstance(hit, str):
        resolved = hit
    if not resolved or not os.path.exists(resolved):
        return None
    # Drop poisoned mappings (e.g. MFT.csv → $MFT from an earlier bug).
    if not _compatible_candidate(path, resolved):
        try:
            kn.get("known_paths", {}).pop(_norm(path), None)
            save_knowledge(case_dir, kn)
        except OSError:
            pass
        return None
    return resolved


def _is_tabular_name(name: str) -> bool:
    return Path(name).suffix.casefold() in _TABULAR_EXTS


def _compatible_candidate(guessed: str, candidate: str) -> bool:
    """Reject cross-kind rewrites (tabular guess → raw $MFT, etc.)."""
    g_name = Path(guessed).name
    c_name = Path(candidate).name
    if _is_tabular_name(g_name):
        if _RAW_NTFS_META_RE.match(c_name):
            return False
        if not _is_tabular_name(c_name):
            # Allow directory candidates only for discovery_next, not resolve
            if os.path.isdir(candidate):
                return False
            return False
    g_ext = Path(g_name).suffix.casefold()
    c_ext = Path(c_name).suffix.casefold()
    if g_ext and c_ext and g_ext in _TABULAR_EXTS and c_ext in _TABULAR_EXTS:
        return True
    if g_ext and c_ext and g_ext == c_ext:
        return True
    if not g_ext:
        return True
    # Same stem family without forcing extension equality for raw artifacts
    if not _is_tabular_name(g_name):
        return _fuzzy_score(g_name, c_name) >= _AUTO_RESOLVE_MIN_SCORE
    return c_ext == g_ext


def _abs_case_path(case_dir: str | os.PathLike, path: str) -> str:
    p = (path or "").strip()
    if not p:
        return p
    if os.path.isabs(p):
        return _norm(p)
    return _norm(str(Path(case_dir).resolve() / p))


def _rank_candidate(guessed: str, candidate: str) -> int:
    """Basename fuzzy score + host affinity + where the candidate lives
    (a parser output folder, Atlas's analysis/, a raw filesystem)."""
    score = _fuzzy_score(Path(guessed).name, Path(candidate).name)
    g = guessed.replace("\\", "/")
    c = candidate.replace("\\", "/")
    # Host tokens are read below evidence/: a case id shaped like a host
    # name (CASE-2031-001) sits above it in every path and would favour
    # every host alike.
    g_below = g.rpartition("/evidence/")[2]
    c_below = c.rpartition("/evidence/")[2]
    for tok in _HOST_TOKEN_RE.findall(g_below):
        if tok and tok.casefold() in c_below.casefold():
            score += 30
            break
    if _is_tabular_name(Path(guessed).name):
        if PARSER_DIR_RE.search(c):
            score += 20
        if re.search(r"(?i)(?:^|/)analysis/", c):
            score += 10
        if RAW_FS_DIR_RE.search(c):
            score -= 50
        if re.search(r"(?i)MFTECmd", c) and re.search(
                r"(?i)mft|usn|journal", Path(guessed).name):
            score += 15
    return score


def _same_kind_of_file(candidate: str, guessed_name: str) -> bool:
    """A stand-in for a missing path must at least be the same kind of
    file: the guessed extension is kept. ``MFT.csv`` may resolve to
    ``mft.MFTECmd.timeline.csv`` (a parser export under a longer name),
    but a grep aimed at ``SRV-01_MFT.csv`` — a file never produced —
    was quietly run against ``srv-01_mft_strings.txt`` because both
    counted as "tabular", and the model read
    "0 matches" as a fact about the CSV. A different extension stays a
    candidate the model has to pick on purpose."""
    g_ext = Path(guessed_name).suffix.casefold()
    return not g_ext or Path(candidate).suffix.casefold() == g_ext


def _pick_unique(scored: list[tuple[int, str]]) -> str | None:
    """Return best path when unique or a clear score winner."""
    if not scored:
        return None
    scored = sorted(scored, key=lambda t: t[0], reverse=True)
    top_s, top_p = scored[0]
    if top_s < _AUTO_RESOLVE_MIN_SCORE:
        return None
    if len(scored) == 1:
        return top_p
    second_s = scored[1][0]
    if top_s >= second_s + _AUTO_RESOLVE_MARGIN:
        return top_p
    # Exact basename (score 100+) beats a weaker second hit
    if top_s >= 100 and top_s > second_s:
        return top_p
    return None


def _list_compatible_in_dir(parent: str, guessed_name: str) -> list[tuple[int, str]]:
    try:
        names = [n for n in os.listdir(parent) if not n.startswith(".")]
    except OSError:
        return []
    out: list[tuple[int, str]] = []
    for n in names:
        full = os.path.join(parent, n)
        if not _compatible_candidate(guessed_name, full):
            continue
        # Also score against guessed full path context via parent join later
        s = _fuzzy_score(guessed_name, n)
        if s >= _AUTO_RESOLVE_MIN_SCORE:
            out.append((s, full))
    return out


def _folder_names(path: Path) -> list[str]:
    try:
        return [e.name for e in os.scandir(path)]
    except (OSError, ValueError):
        return []


def _is_raw_extract(path: Path) -> bool:
    """``path``, or a drive-letter folder directly below it, is the root of a
    raw Windows filesystem."""
    names = _folder_names(path)
    if looks_like_raw_fs_root(names):
        return True
    return any(len(n) == 1 and looks_like_raw_fs_root(_folder_names(path / n))
               for n in names)


def _parallel_parsed_dirs(guessed: str, case_dir: str | os.PathLike | None) -> list[str]:
    """The same host's parser-export folder, when the guess sits in its raw
    extract.

    A delivery can keep a host's raw filesystem extract and its parser exports
    in two sibling trees, ``<root>/<tree A>/<host>/…`` and
    ``<root>/<tree B>/<host>/…``, under tree names that differ from one
    delivery to the next; a table name guessed in the raw extract can exist in
    the other tree. The host is the deepest folder of the guess that reads as
    a host name (``_HOST_TOKEN_RE``), or else the folder two levels below
    ``evidence/``. It maps only raw to parsed: the guessed host folder must be
    a raw extract and a twin must not be one. A tree that itself reads as a
    host means the layout is host-first (``evidence/<host>/…``): its siblings
    are other hosts, so nothing is mapped. Twins holding a parser output
    folder come first; each is returned with its subfolders one level down.
    """
    if not case_dir:
        return []
    path = Path(_abs_case_path(case_dir, guessed))
    # A case reached through a symlink: the guess may use either form.
    roots = (Path(os.path.abspath(case_dir)), Path(os.path.realpath(case_dir)))
    root = next((r for r in roots if path.is_relative_to(r)), None)
    if root is None:
        return []
    ev = root / "evidence"
    # The search stays inside the evidence tree (or the case, for a guess
    # outside evidence/): no sibling above it is a delivery tree.
    floor = ev if path.is_relative_to(ev) else root
    parts = path.parts if not path.suffix else path.parts[:-1]   # folders only
    hosts = [i for i in range(len(parts) - 1, len(floor.parts), -1)
             if _HOST_TOKEN_RE.fullmatch(parts[i])]
    if floor == ev and len(ev.parts) + 1 < len(parts):
        hosts.append(len(ev.parts) + 1)
    for h in hosts:
        tree, host = parts[h - 1], parts[h]
        if _HOST_TOKEN_RE.fullmatch(tree) or not _is_raw_extract(Path(*parts[:h + 1])):
            continue
        parent = Path(*parts[:h - 1])
        siblings = sorted(n for n in _folder_names(parent)
                          if n != tree and not n.startswith("."))
        twins: list[tuple[int, str, list[str]]] = []
        for sib in siblings:
            twin = parent / sib / host
            try:
                if not twin.is_dir() or _is_raw_extract(twin):
                    continue
                kids = sorted(e.path for e in os.scandir(twin) if e.is_dir())
            except (OSError, ValueError):
                continue
            parser_first = 0 if any(PARSER_DIR_RE.search(k.replace("\\", "/")) for k in kids) else 1
            twins.append((parser_first, str(twin), kids))
        if twins:
            found: list[str] = []
            for _order, twin, kids in sorted(twins):
                found.append(_norm(twin))
                found += [_norm(k) for k in kids]
            return found
    return []


def _candidates_from_inventory(case_dir: str | os.PathLike, guessed: str) -> list[str]:
    """Pull candidate paths from inventory stamp / assessment / catalog."""
    out: list[str] = []
    root = Path(case_dir).resolve()

    # Live inventory JSON
    try:
        inv_path = root / ".atlas" / "evidence_inventory.json"
        if inv_path.is_file():
            inv = json.loads(inv_path.read_text(encoding="utf-8"))
            assessment = inv.get("assessment") or inv
            for p in (assessment.get("already_processed") or {}).get("paths") or []:
                if isinstance(p, str):
                    out.append(p)
            for key in ("high_value_parsed", "already_processed_paths"):
                for p in assessment.get(key) or []:
                    if isinstance(p, str):
                        out.append(p)
            samples = (assessment.get("what_exists") or {}).get("sample_paths") or {}
            if isinstance(samples, dict):
                for paths in samples.values():
                    if isinstance(paths, list):
                        out.extend(str(x) for x in paths if isinstance(x, str))
    except Exception:
        pass

    # Evidence catalog units
    try:
        from core.evidence_catalog import load_catalog
        units = (load_catalog(root).get("units") or {})
        for u in units.values():
            if isinstance(u, dict) and u.get("path"):
                out.append(str(u["path"]))
    except Exception:
        pass

    abs_paths: list[str] = []
    for p in out:
        if not p:
            continue
        ap = _abs_case_path(case_dir, p)
        if os.path.exists(ap) and _compatible_candidate(guessed, ap):
            abs_paths.append(ap)

    ranked = sorted(
        set(abs_paths),
        key=lambda p: _rank_candidate(guessed, p),
        reverse=True,
    )
    return [
        p for p in ranked
        if _rank_candidate(guessed, p) >= _AUTO_RESOLVE_MIN_SCORE
    ][:12]


def _discovery_next_for(
    guessed: str,
    *,
    parent: str | None,
    candidates: list[str],
    parallel_dirs: list[str],
) -> dict[str, Any]:
    if candidates:
        top_parent = os.path.dirname(candidates[0])
        return {
            "tool": "misc.list_evidence_dir",
            "arguments": {"path": top_parent},
            "reason": (
                "Related paths found via inventory/catalog. List that "
                "directory and open an exact basename — do not retry "
                f"{Path(guessed).name!r} under the wrong tree."
            ),
        }
    if parallel_dirs:
        return {
            "tool": "misc.list_evidence_dir",
            "arguments": {"path": parallel_dirs[0]},
            "reason": (
                "A folder of this host's name exists in a sibling tree of "
                "the evidence and may hold its parser exports (confirm it "
                "is this host). List it with misc.list_evidence_dir, then "
                "query an exact file name from the listing; a folder is not "
                "a table, and names invented inside a raw extract do not "
                "exist."
            ),
        }
    if parent and os.path.isdir(parent):
        return {
            "tool": "misc.list_evidence_dir",
            "arguments": {"path": parent},
            "reason": (
                "Parent directory exists. List it authoritatively before "
                "opening any basename — do not invent filenames."
            ),
        }
    return {
        "tool": "misc.inventory_evidence",
        "arguments": {},
        "reason": (
            "No existing parent found. Run authoritative inventory before "
            "any path-based tool."
        ),
    }


def try_resolve_missing_path(
    missing_path: str,
    *,
    case_dir: str | os.PathLike | None = None,
) -> dict[str, Any]:
    """Attempt authoritative resolution for one missing path.

    Returns dict with keys:
      resolved: str | None
      method: known | sibling_unique | parallel_tools | inventory | None
      candidates: list[str]
      discovery_next: dict (tool + args) | None
      hint: str
    """
    path = _norm(missing_path)
    result: dict[str, Any] = {
        "guessed": path,
        "resolved": None,
        "method": None,
        "candidates": [],
        "discovery_next": None,
        "hint": format_missing_path_hint(path),
    }

    # 1) Prior discovery knowledge (compat-checked)
    if case_dir:
        known = lookup_known(case_dir, path)
        if known:
            result["resolved"] = known
            result["method"] = "known"
            return result

    parent = os.path.dirname(path)
    guessed_name = os.path.basename(path)
    parallel = _parallel_parsed_dirs(path, case_dir)

    # 2) Unique high-confidence *compatible* sibling in existing parent
    sibling_hits: list[tuple[int, str]] = []
    if parent and os.path.isdir(parent):
        raw = _list_compatible_in_dir(parent, guessed_name)
        sibling_hits = [
            (_rank_candidate(path, full), full) for _, full in raw
        ]
        result["candidates"] = [p for _, p in sorted(
            sibling_hits, key=lambda t: t[0], reverse=True)[:8]]
        picked = _pick_unique(sibling_hits)
        if picked and _same_kind_of_file(picked, guessed_name):
            result["resolved"] = picked
            result["method"] = "sibling_unique"
            return result

    # 2b) The same host's parser-export folder in a sibling evidence tree
    parallel_hits: list[tuple[int, str]] = []
    for d in parallel:
        for s, full in _list_compatible_in_dir(d, guessed_name):
            parallel_hits.append((_rank_candidate(path, full), full))
    if parallel_hits:
        parallel_hits = sorted(set(parallel_hits), key=lambda t: t[0], reverse=True)
        # merge into candidates for refusal payloads
        merged = list(dict.fromkeys(
            result["candidates"] + [p for _, p in parallel_hits]
        ))
        result["candidates"] = merged[:8]
        picked = _pick_unique(parallel_hits)
        # A silent rewrite only into a parser's output folder: any other
        # twin stays a candidate the model has to open on purpose.
        if (picked and _same_kind_of_file(picked, guessed_name)
                and PARSER_DIR_RE.search(picked.replace("\\", "/"))):
            result["resolved"] = picked
            result["method"] = "parallel_tools"
            return result

    # 3) Inventory / catalog (always — even when parent exists)
    if case_dir:
        inv_hits = _candidates_from_inventory(case_dir, path)
        if inv_hits:
            result["candidates"] = list(dict.fromkeys(
                result["candidates"] + inv_hits
            ))[:8]
            scored = [(_rank_candidate(path, p), p) for p in inv_hits]
            picked = _pick_unique(scored)
            if picked:
                result["resolved"] = picked
                result["method"] = "inventory"
                return result
            result["discovery_next"] = _discovery_next_for(
                path, parent=parent, candidates=inv_hits,
                parallel_dirs=parallel)
            return result

    # 4) Parent / parallel discovery nudge (no silent invent)
    if parent and os.path.isdir(parent) or parallel:
        result["discovery_next"] = _discovery_next_for(
            path, parent=parent, candidates=result["candidates"],
            parallel_dirs=parallel)
        return result

    # 5) Climb to nearest existing ancestor for listing
    climb = parent
    while climb and climb not in ("/", ""):
        if os.path.isdir(climb):
            result["discovery_next"] = {
                "tool": "misc.list_evidence_dir",
                "arguments": {"path": climb},
                "reason": (
                    "Path missing; list nearest existing directory, then "
                    "use only names that appear in the listing."
                ),
            }
            return result
        climb = os.path.dirname(climb)

    result["discovery_next"] = _discovery_next_for(
        path, parent=None, candidates=[], parallel_dirs=[])
    return result


def build_discovery_refusal(
    tool_name: str,
    missing_items: list[dict[str, Any]],
    *,
    repeat: bool = False,
) -> dict[str, Any]:
    """Structured TOOL INFO payload for discovery-first refusals."""
    first = missing_items[0] if missing_items else {}
    discovery = first.get("discovery_next") or {
        "tool": "misc.list_evidence_dir",
        "arguments": {},
        "reason": "Discover before guessing.",
    }
    return {
        "success": False,
        "gate": "discovery_first",
        "principle": "Authoritative discovery always overrides LLM assumptions.",
        "error": (
            f"{tool_name} refused: filesystem path not established by "
            f"discovery. Invented path(s) blocked"
            + (" (repeat — do not retry the same guess)." if repeat else ".")
        ),
        "missing": [
            {
                "param": m.get("param"),
                "guessed": m.get("guessed"),
                "candidates": (m.get("candidates") or [])[:8],
                "hint": m.get("hint"),
            }
            for m in missing_items
        ],
        "discovery_next": discovery,
        "summary": (
            "Do not invent filenames or layouts. Call discovery_next, update "
            "your path knowledge from the listing/inventory, then retry once "
            "with an exact discovered path."
        ),
        "hint": first.get("hint") or format_missing_path_hint(
            str(first.get("guessed") or "")
        ),
    }


def check_and_resolve_input_paths(
    tool_name: str,
    args: dict,
    *,
    case_dir: str | os.PathLike | None = None,
) -> tuple[dict, list[dict[str, Any]]]:
    """Resolve or refuse filesystem input args under discovery-first rules.

    Returns ``(args, resolutions)`` when all inputs exist (possibly rewritten).
    Raises ``ValueError`` with a JSON-serialisable refusal dict when blocked
    (caller turns that into ToolError + PROTOCOL_MARKER).
    """
    from core.paths import INPUT_PATH_PARAM_NAMES

    # Discovery tools: still require existing *parent* when listing, but do
    # not apply invent-path auto-resolve loops against themselves.
    is_discovery = bool(DISCOVERY_TOOL_RE.search(tool_name or ""))

    new_args = dict(args)
    resolutions: list[dict[str, Any]] = []
    missing_payloads: list[dict[str, Any]] = []
    repeat = False

    for key in INPUT_PATH_PARAM_NAMES:
        val = new_args.get(key)
        if not isinstance(val, str):
            continue
        path = _norm(val)
        if not path:
            continue
        if os.path.exists(path):
            # Record successful use as knowledge
            if case_dir:
                remember_known_path(case_dir, path, path, source="verified")
            continue

        # Repeat identical failed guess → hard stop (no forensic retry storm)
        if case_dir and failed_guess_count(case_dir, path) >= 1 and not is_discovery:
            repeat = True
            info = try_resolve_missing_path(path, case_dir=case_dir)
            info["param"] = key
            missing_payloads.append(info)
            continue

        info = try_resolve_missing_path(path, case_dir=case_dir)
        info["param"] = key

        if info.get("resolved") and os.path.exists(info["resolved"]):
            new_args[key] = info["resolved"]
            resolutions.append({
                "param": key,
                "from": path,
                "to": info["resolved"],
                "method": info.get("method"),
            })
            if case_dir:
                remember_known_path(
                    case_dir, path, info["resolved"],
                    source=str(info.get("method") or "discovery"),
                )
            continue

        if case_dir and not is_discovery:
            remember_failed_guess(
                case_dir, path, hint=str(info.get("hint") or ""))
        missing_payloads.append(info)

    if missing_payloads and not is_discovery:
        raise ValueError(
            json.dumps(
                build_discovery_refusal(
                    tool_name, missing_payloads, repeat=repeat),
                ensure_ascii=False,
            )
        )

    # Discovery tools with missing path: keep legacy-style refusal but enriched
    if missing_payloads and is_discovery:
        specs = [
            f"{m.get('param')}={m.get('guessed')!r}" for m in missing_payloads
        ]
        from core.path_hints import enrich_missing_paths_message
        raise ValueError(
            f"{tool_name} refused: input path(s) do not exist: "
            + ", ".join(specs)
            + enrich_missing_paths_message(specs)
        )

    return new_args, resolutions


def quarantine_guessed_paths(
    paths: list[str] | None,
    case_dir: str | os.PathLike | None,
) -> list[str]:
    """Drop paths that are recorded failed guesses (DAIR focus sanitisation)."""
    if not paths:
        return []
    out: list[str] = []
    for p in paths:
        if not isinstance(p, str) or not p.strip():
            continue
        if case_dir and is_failed_guess(case_dir, p):
            continue
        if not os.path.exists(os.path.expanduser(p)):
            # Unverified path — do not let speculation become priority focus
            continue
        out.append(p)
    return out


def discovery_priority_tools() -> list[str]:
    """Canonical discovery work-order tools for DAIR injection."""
    return [
        "misc.inventory_evidence",
        "misc.list_evidence_dir",
    ]
