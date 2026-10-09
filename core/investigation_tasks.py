"""Investigation task queue — case-driven work items (V1, lightweight).

CASE.md is the investigator inbox (append-only requests). This module is
Atlas's durable task SoT under ``.atlas/investigation_tasks.json``.

Matching is deterministic: exact normalized-text equality only. When unsure,
create a new task — never fuzzy-merge.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = "1.0"

TASK_STATUSES = frozenset({
    "open",
    "in_progress",
    "partial",
    "answered",
    "blocked_missing_evidence",
    "reopened",
    "dropped",
})

# Legacy alias — claim_graph / analyst_context keep "withdrawn"; tasks use "dropped".
_STATUS_ALIASES = {
    "withdrawn": "dropped",
}


def normalize_task_status(status: str) -> str:
    """Map legacy task status aliases to the current enum value."""
    return _STATUS_ALIASES.get(status, status)

# Unanswered / still-actionable statuses dropped when the CASE.md line disappears.
_DROPPABLE = frozenset({
    "open", "in_progress", "partial", "reopened", "blocked_missing_evidence",
})
# Back-compat name for callers that still import the old constant.
_WITHDRAWABLE = _DROPPABLE

# Derived revisit tasks are not CASE.md lines, so reconciliation must not treat
# their absence from the brief as a removal. They are marked by this text prefix
# rather than a field, so the marker has to be applied by add_derived_task
# itself — a caller that forgets it gets a task that vanishes on the next run.
DERIVED_PREFIX = "[derived]"

_ACTIONABLE = frozenset({
    "open", "in_progress", "partial", "reopened", "blocked_missing_evidence",
})
ACTIONABLE_STATUSES = _ACTIONABLE

# Heading aliases for the investigation-request inbox section.
_SECTION_HEADINGS = frozenset({
    "investigation requests",
    "scope",
    "requests",
})

# A thematic break: three or more of one of -, * or _, spaces or tabs between
# (the CommonMark rule, which also gives a break precedence over a list
# item), at any indentation: an indented run of one break character is a code
# line or a nested break, never a request. A separator, never a bullet. The
# pattern has no group, so group(1) of _BULLET_RE stays the bullet's text.
_THEMATIC_BREAK = r"\s*(?:(?:-[ \t]*){3,}|(?:\*[ \t]*){3,}|(?:_[ \t]*){3,})"
_THEMATIC_BREAK_RE = re.compile(rf"^{_THEMATIC_BREAK}$")

_BULLET_RE = re.compile(
    rf"^(?!{_THEMATIC_BREAK}$)\s*(?:[-*+]|\d+[.)])\s+(.+?)\s*$"
)
_HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*$")
_CASE_ID_LINE_RE = re.compile(
    r"(?i)^\s*(?:\*\*)?case\s*id(?:\*\*)?\s*[:\|]\s*(.+?)\s*$"
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tasks_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "investigation_tasks.json"


def empty_tasks(case_id: str = "") -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id or "",
        "updated_at": _utcnow(),
        "next_id": 1,
        "tasks": [],
    }


def _migrate_task_statuses(store: dict[str, Any]) -> bool:
    """Rewrite legacy task statuses in-place. Returns True if anything changed."""
    changed = False
    for t in store.get("tasks") or []:
        if not isinstance(t, dict):
            continue
        status = t.get("status")
        mapped = _STATUS_ALIASES.get(status)
        if mapped and mapped != status:
            t["status"] = mapped
            changed = True
    return changed


def _normalize_store(store: Any) -> dict[str, Any]:
    """Keep the tasks that are tasks. A junk entry (a string, a null, a dict
    with no text) or an unknown status must not stop the real questions
    from being listed or answered."""
    if not isinstance(store, dict):
        return empty_tasks()
    tasks = store.get("tasks")
    if not isinstance(tasks, list):
        store["tasks"] = []
        return store
    clean: list[dict[str, Any]] = []
    for i, t in enumerate(tasks, start=1):
        if not isinstance(t, dict):
            continue
        text = str(t.get("text") or "").strip()
        if not text:
            continue
        t["text"] = text
        t.setdefault("id", f"task-{i:04d}")
        status = normalize_task_status(str(t.get("status") or "open"))
        t["status"] = status if status in TASK_STATUSES else "open"
        if not isinstance(t.get("related_claim_ids"), list):
            t["related_claim_ids"] = []
        if isinstance(t.get("parts"), list) and t["parts"]:
            # The status is what the parts say, never what was stored.
            from core.request_parts import derive_status
            t["status"] = derive_status(t)
        clean.append(t)
    store["tasks"] = clean
    return store


def load_tasks(case_dir: str | os.PathLike) -> dict[str, Any]:
    path = tasks_path(case_dir)
    if not path.is_file():
        return empty_tasks(Path(case_dir).resolve().name)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty_tasks(Path(case_dir).resolve().name)
    if not isinstance(data, dict):
        return empty_tasks()
    data.setdefault("schema_version", SCHEMA_VERSION)
    data.setdefault("tasks", [])
    data.setdefault("next_id", 1)
    if not isinstance(data["tasks"], list):
        data["tasks"] = []
    if _migrate_task_statuses(data):
        try:
            save_tasks(case_dir, data)
        except OSError:
            pass
    return _normalize_store(data)


def save_tasks(case_dir: str | os.PathLike, store: dict[str, Any]) -> Path:
    path = tasks_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    store = dict(store)
    store["schema_version"] = SCHEMA_VERSION
    store["updated_at"] = _utcnow()
    path.write_text(
        json.dumps(store, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    try:
        from core.investigation_orchestrator import mark_state_dirty
        mark_state_dirty(case_dir, reason="investigation_tasks_save")
    except Exception:
        pass
    return path


def normalize_request_text(text: str) -> str:
    """Deterministic normalization for exact-match fingerprints."""
    return re.sub(r"\s+", " ", (text or "").strip()).casefold()


def fingerprint_text(text: str) -> str:
    norm = normalize_request_text(text)
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


def read_case_markdown(case_dir: str | os.PathLike) -> str:
    """Return CASE.md or CLAUDE.md text (empty if neither exists)."""
    root = Path(case_dir).resolve()
    for name in ("CASE.md", "CLAUDE.md"):
        p = root / name
        if p.is_file():
            try:
                return p.read_text(encoding="utf-8")
            except OSError:
                return ""
    return ""


def write_case_markdown(case_dir: str | os.PathLike, text: str) -> Path:
    """Replace the case file whole: written beside it and renamed over it,
    so a run reading the brief at that moment sees the old text or the
    new, never half of either."""
    root = Path(case_dir).resolve()
    path = root / "CASE.md"
    if not path.is_file() and (root / "CLAUDE.md").is_file():
        path = root / "CLAUDE.md"
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    return path


def _strip_noncontent_markdown(markdown: str) -> str:
    """Remove Markdown constructs that are never investigator input.

    - HTML comments (``<!-- … -->``, multi-line; an unterminated comment is
      stripped to end-of-file). CASE.md templates carry documentation about
      Atlas's internals inside comments — commented text is not a request.
    - Fenced code blocks (``` / ~~~). Examples and file listings inside
      fences are illustrations, not requests.

    This runs before any section/bullet parsing so documentation can never
    leak into the task store regardless of which section it sits in.
    """
    lines = strip_html_comments(markdown).splitlines()
    return "\n".join(line for line, fenced in zip(lines, fenced_flags(lines))
                     if not fenced)


def strip_html_comments(markdown: str) -> str:
    """``markdown`` without HTML comments (``<!-- … -->``, multi-line; an
    unterminated comment is stripped to end-of-file). A brief's comments
    document the template for the analyst; no parser and no prompt reads
    them as the analyst's input."""
    # String scan — regex with DOTALL can't express the "unterminated
    # comment swallows the rest" rule cleanly.
    parts: list[str] = []
    rest = markdown
    while True:
        start = rest.find("<!--")
        if start == -1:
            parts.append(rest)
            break
        parts.append(rest[:start])
        end = rest.find("-->", start + 4)
        if end == -1:
            break  # unterminated comment: drop everything after it
        rest = rest[end + 3:]
    return "".join(parts)


_FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")


def _fence_walk(lines: list[str]):
    """Per line: whether it belongs to a fenced code block (``` / ~~~),
    the fence lines included, and the character of the block open after
    it. A block closes on a fence of its own character; an unclosed one
    runs to the end, as Markdown renders it."""
    open_char = ""
    for line in lines:
        m = _FENCE_RE.match(line)
        if m and not open_char:
            open_char = m.group(1)[0]
            yield True, open_char
        elif m and m.group(1)[0] == open_char:
            open_char = ""
            yield True, open_char
        else:
            yield bool(open_char), open_char


def fenced_flags(lines: list[str]) -> list[bool]:
    """Per line, whether it belongs to a fenced code block."""
    return [fenced for fenced, _ in _fence_walk(lines)]


def open_fence(lines: list[str]) -> str:
    """The character of a fenced block still open after ``lines``; ""
    when every block is closed. A text cut inside a block closes it."""
    char = ""
    for _, char in _fence_walk(lines):
        pass
    return char


# Lines the parsers would read if they were not inside a block: a heading, a
# bullet or numbered item, a table row.
_PARSED_SHAPE_RE = re.compile(r"^\s{0,3}#{1,6}\s|^\s*(?:[-*+]|\d+[.)])\s+\S|^\s*\|")


def unclosed_fence(markdown: str) -> dict[str, Any] | None:
    """Where a fenced block that never closes opens in a brief, and what it hides.

    An unclosed block runs to the end, as Markdown renders it, so every
    request, Evidence Links row and fact after its opening line reads as
    code and no parser sees it. Returns ``{"line": <1-based line of the
    opening fence>, "hidden": [<lines after it shaped like headings,
    bullets or table rows>], "hidden_requests": <requests the brief would
    hold if the block were closed, less those it holds>}``, or None when
    every block closes or nothing of that shape follows. HTML comments are
    blanked as the parsers drop them, keeping the file's own numbering.
    Like the parsers, a block closes on any fence of its own character.
    """
    from core.case_knowledge import comment_line_indexes

    lines = (markdown or "").splitlines()
    commented = comment_line_indexes(lines)
    view = ["" if i in commented else line for i, line in enumerate(lines)]
    opener, char = None, ""
    for i, line in enumerate(view):
        m = _FENCE_RE.match(line)
        if m and not char:
            opener, char = i, m.group(1)[0]
        elif m and m.group(1)[0] == char:
            opener, char = None, ""
    if opener is None:
        return None
    hidden = [view[i].strip() for i in range(opener + 1, len(view))
              if _PARSED_SHAPE_RE.match(view[i])]
    if not hidden:
        return None
    closed = "\n".join(view[:opener] + view[opener + 1:])
    gained = len(parse_case_requests(closed)) - len(parse_case_requests(markdown))
    return {"line": opener + 1, "hidden": hidden, "hidden_requests": max(0, gained)}


_EMPHASIS_PAIR_RE = re.compile(r"(\*\*|__)(.+?)\1")
_EMPHASIS_SINGLE_RE = re.compile(r"(?<![\w*])([*_])(?=\S)(.+?)(?<=\S)\1(?![\w*])")


def _strip_inline_emphasis(text: str) -> str:
    """``**Was it compromised?**`` is the question, not its markup: the
    stars otherwise survive into task text, headings and the report."""
    text = _EMPHASIS_PAIR_RE.sub(r"\2", text)
    return _EMPHASIS_SINGLE_RE.sub(r"\2", text).strip()


# The objective a run falls back to when the case names none. A run with no
# question would otherwise be refused outright, which is the wrong answer for
# a disk handed over with "look at it": that IS the question. Deliberately
# broad — it puts no host, artifact or theory into the run that the evidence
# did not.
DEFAULT_OBJECTIVE = "What happened on the Host(s)?"


def parse_case_request_items(markdown: str) -> list[dict[str, Any]]:
    """The investigation requests of CASE.md / CLAUDE.md as items.

    Each item is ``{"text", "children", "first_line"}``: the request's
    whole text, its nested bullets (each joined the same way), and the
    request's first physical line as an earlier reader took it (marker
    removed, emphasis stripped), which is how a store written by that reader
    is recognised.

    Preferred: bullet/numbered lines under ``## Investigation Requests``
    (aliases: Scope, Requests).

    Compat: if no such section exists, collect bullets from the body while
    skipping known metadata / evidence / output headings.

    Structural rules (CommonMark list items):
    - anything inside HTML comments or fenced code blocks is not read
      (see :func:`_strip_noncontent_markdown`)
    - a line after a bullet that is not blank, not a heading and not a
      bullet continues the item (an indented continuation or a lazy one);
      a blank line or a heading ends it
    - nested bullets (indent >= 2) are the item's children, not requests
    """
    if not markdown or not markdown.strip():
        return []

    lines = _strip_noncontent_markdown(markdown).splitlines()
    section_items: list[dict[str, Any]] = []
    in_section = False
    found_section = False
    skip_headings = frozenset({
        "case metadata", "evidence files", "output directories",
        "mounted", "investigation discipline", "second brain",
        "evidence integrity",
        "evidence links", "evidence map", "hosts and evidence",
        "hosts & evidence", "evidence inventory",
        # The analyst's prior knowledge is leads, never requests
        # (core.case_knowledge reads it).
        "what you already know", "what we already know", "prior knowledge",
        "known indicators", "analyst notes", "background",
    })

    body_items: list[dict[str, Any]] = []
    in_skip = False
    # The item being read: its lines, its children's lines, and which of
    # the two the next continuation line belongs to.
    current: dict[str, Any] | None = None

    def _close() -> None:
        nonlocal current
        if current is None:
            return
        text = _strip_inline_emphasis(" ".join(current["lines"]).strip())
        first = _strip_inline_emphasis(current["lines"][0].strip()) if current["lines"] else ""
        children = [_strip_inline_emphasis(" ".join(c).strip()) for c in current["children"]]
        item = {"text": text, "children": [c for c in children if c], "first_line": first}
        if text and not _CASE_ID_LINE_RE.match(text):
            if found_section:
                if current["in_section"]:
                    section_items.append(item)
            elif not current["in_skip"]:
                body_items.append(item)
        current = None

    for line in lines:
        hm = _HEADING_RE.match(line)
        if hm:
            _close()
            title = hm.group(1).strip().casefold()
            # Strip trailing markdown emphasis
            title = title.strip("*_ ")
            if title in _SECTION_HEADINGS:
                found_section = True
                in_section = True
                in_skip = False
            else:
                in_section = False
                in_skip = title in skip_headings or title.startswith("case:")
            continue
        if not line.strip() or _THEMATIC_BREAK_RE.match(line):
            # A break ends the item above as a blank line does: CommonMark
            # lets it interrupt a list item, so it is never its continuation.
            _close()
            continue
        bm = _BULLET_RE.match(line)
        if bm:
            indent = len(line) - len(line.lstrip(" \t"))
            if indent >= 2 and current is not None:
                # A nested bullet is a child of the request above.
                current["children"].append([bm.group(1).strip()])
                current["tail"] = "child"
                continue
            _close()
            current = {"lines": [bm.group(1).strip()], "children": [], "tail": "item",
                       "in_section": in_section, "in_skip": in_skip}
            continue
        if current is None:
            continue
        # A continuation line of the item or of its last child.
        cont = line.strip()
        if current["tail"] == "child" and current["children"]:
            current["children"][-1].append(cont)
        else:
            current["lines"].append(cont)
    _close()

    if found_section:
        return section_items
    return body_items


def parse_case_requests(markdown: str) -> list[str]:
    """The investigation request texts (see :func:`parse_case_request_items`)."""
    return [item["text"] for item in parse_case_request_items(markdown)]


def _next_task_id(store: dict[str, Any]) -> str:
    n = int(store.get("next_id") or 1)
    store["next_id"] = n + 1
    return f"task-{n:04d}"


def _make_task(store: dict[str, Any], text: str, *, status: str = "open") -> dict[str, Any]:
    now = _utcnow()
    status = normalize_task_status(status)
    return {
        "id": _next_task_id(store),
        "text": text.strip(),
        "status": status if status in TASK_STATUSES else "open",
        "related_claim_ids": [],
        "superseded_by": "",
        "created_at": now,
        "updated_at": now,
    }


def list_tasks(
    case_dir: str | os.PathLike,
    *,
    statuses: Optional[set[str] | frozenset[str]] = None,
) -> list[dict[str, Any]]:
    store = load_tasks(case_dir)
    tasks = list(store.get("tasks") or [])
    if statuses is not None:
        tasks = [t for t in tasks if t.get("status") in statuses]
    return tasks


def actionable_tasks(case_dir: str | os.PathLike) -> list[dict[str, Any]]:
    return list_tasks(case_dir, statuses=_ACTIONABLE)


def format_tasks_for_prompt(case_dir: str | os.PathLike) -> str:
    """Compact open-work summary for system/user prompts."""
    tasks = actionable_tasks(case_dir)
    if not tasks:
        answered = list_tasks(case_dir, statuses=frozenset({"answered"}))
        if not answered:
            return (
                "# Investigation Tasks\n\n"
                "(none yet — ensure CASE.md has an Investigation Requests section)\n"
            )
        return (
            "# Investigation Tasks\n\n"
            f"All inbox requests answered ({len(answered)}). "
            "Append new requests to CASE.md to continue.\n"
        )
    lines = ["# Investigation Tasks", ""]
    for t in tasks:
        lines.append(f"- [{t.get('status')}] **{t.get('id')}**: {t.get('text')}")
        from core.request_parts import open_parts
        pending = open_parts(t)
        if pending:
            lines.append("  open parts: " + "; ".join(
                f"{p['id']} {p['text']} ({p['type']})" for p in pending))
    lines.append("")
    return "\n".join(lines)


def objectives_from_tasks(case_dir: str | os.PathLike) -> str:
    """Build a CASE_QUESTION-style string from actionable tasks."""
    tasks = actionable_tasks(case_dir)
    if not tasks:
        return ""
    if len(tasks) == 1:
        return str(tasks[0].get("text") or "").strip()
    parts = [f"{t.get('id')}: {t.get('text')}" for t in tasks]
    return "Investigate the following open requests:\n- " + "\n- ".join(parts)


def _disk_access_blocks_missing_evidence(
    case_dir: str | os.PathLike,
    task_text: str,
) -> Optional[str]:
    """Refuse blocked_missing_evidence when disk media is already staged.

    A disk task marked blocked after export, while analysis/*.raw sits
    registered on mount_plan and TSK never ran, is an access-stage failure,
    not missing evidence.

    Authority: ``core.evidence_access`` (mount_plan + links), not ad-hoc checks.
    """
    try:
        from core.evidence_access import refuse_blocked_missing_evidence
        return refuse_blocked_missing_evidence(case_dir, task_text)
    except Exception:
        return None


def repair_tasks_against_access(
    case_dir: str | os.PathLike,
    *,
    persist: bool = True,
) -> dict[str, Any]:
    """Reopen tasks wrongly parked as blocked_missing_evidence while media staged."""
    try:
        from core.evidence_access import refuse_blocked_missing_evidence
    except Exception:
        return {"success": True, "repaired": []}
    store = load_tasks(case_dir)
    repaired: list[str] = []
    now = _utcnow()
    for t in store.get("tasks") or []:
        if t.get("status") != "blocked_missing_evidence":
            continue
        refuse = refuse_blocked_missing_evidence(
            case_dir, str(t.get("text") or ""),
        )
        if refuse:
            t["status"] = "in_progress"
            t["updated_at"] = now
            t["note"] = (
                "auto-repaired: blocked_missing_evidence contradicted "
                "access stage (media staged/planned)"
            )
            repaired.append(str(t.get("id")))
    if persist and repaired:
        save_tasks(case_dir, store)
    return {"success": True, "repaired": repaired}


# A reading (the system baseline) states a fact as well as a claim does.
_SUPPORT_KINDS = frozenset({"claim", "conclusion", "observation"})
_GONE = frozenset({"superseded", "withdrawn", "dropped"})


def active_support(case_dir: str | os.PathLike,
                   claim_ids: list[str] | None) -> list[str]:
    """The subset of ``claim_ids`` that are current beliefs in the graph."""
    ids = [str(c) for c in (claim_ids or []) if c]
    if not ids:
        return []
    try:
        from core.claim_graph import load_graph
        nodes = load_graph(case_dir).get("nodes") or {}
    except Exception:  # noqa: BLE001
        return []
    return [c for c in ids
            if isinstance(nodes.get(c), dict)
            and nodes[c].get("kind") in _SUPPORT_KINDS
            and nodes[c].get("status") not in _GONE]


def answer_candidates(case_dir: str | os.PathLike, *, limit: int = 8,
                      parts: list[dict[str, Any]] | None = None) -> list[str]:
    """Current beliefs an answer could rest on, strongest first — offered
    back to the model when it tries to close a question without any. With
    the open ``parts``, the beliefs that carry a value one of them asks
    for come first (a baseline reading that states the operating system,
    for a part that asks for it), then conclusions, claims and readings."""
    try:
        from core.claim_graph import load_graph
        nodes = load_graph(case_dir).get("nodes") or {}
    except Exception:  # noqa: BLE001
        return []
    rank = {"CONFIRMED": 3, "LIKELY": 2, "SUSPECTED": 1}
    rows = [n for n in nodes.values()
            if isinstance(n, dict) and n.get("kind") in _SUPPORT_KINDS
            and n.get("status") not in _GONE]

    def answers_a_part(n: dict[str, Any]) -> bool:
        if not parts:
            return False
        try:
            from core.answer_values import VALUE_TYPES, bind
        except Exception:  # noqa: BLE001
            return False
        statement = str(n.get("statement") or "")
        for part in parts:
            typ = str(part.get("type") or "")
            if typ in VALUE_TYPES and bind(str(part.get("text") or ""), typ, statement)[0]:
                return True
        return False

    # Conclusions first, then claims, then readings: a baseline's CONFIRMED
    # observations must not push the analyst's own beliefs off the list.
    order = {"conclusion": 0, "claim": 1, "observation": 2}
    rows.sort(key=lambda n: (not answers_a_part(n),
                             order.get(str(n.get("kind")), 3),
                             -rank.get(str(n.get("confidence")).upper(), 0)))
    return [f"{n.get('id')} [{n.get('confidence')}] "
            f"{str(n.get('statement') or '')[:120]}" for n in rows[:limit]]


def _computer_hosts(case_dir) -> list[str]:
    """The hosts whose evidence is a computer's disk, memory or live
    system, from the evidence links: the unit the per-host standard parts
    apply to. Removable media and captures are not hosts."""
    try:
        from core.evidence_links import load_evidence_links
        data = load_evidence_links(case_dir)
    except Exception:  # noqa: BLE001
        return []
    hosts: list[str] = []
    for e in data.get("entries") or []:
        if not isinstance(e, dict):
            continue
        if str(e.get("kind") or "") in ("disk", "memory", "live") and e.get("host"):
            h = str(e["host"]).strip()
            if h and h not in hosts:
                hosts.append(h)
    return hosts


def _graph_nodes(case_dir) -> dict[str, dict]:
    try:
        from core.claim_graph import load_graph
        return dict(load_graph(case_dir).get("nodes") or {})
    except Exception:  # noqa: BLE001
        return {}


def _known_hosts(case_dir) -> list[str]:
    try:
        from core.forensic_citation import known_case_hosts
        return list(known_case_hosts(case_dir))
    except Exception:  # noqa: BLE001
        return []


# The shape ``parts`` takes, shown whole wherever the model is told how to
# close or limit a part: a JSON object, never a string.
PARTS_EXAMPLE = ('{"p2": {"claim_ids": ["C0012"]}, "p3": {"limitation": {"basis": "examined", '
                 '"reason": "<what was read and what it held>", "call_ids": [412]}}}')
PARTS_HOW = ("pass parts as a JSON object, for example " + PARTS_EXAMPLE + ": claim_ids links the "
             "belief that answers a part; limitation records why the evidence cannot answer it, with "
             "basis source_absent (the source is not in the evidence), examined (it was read and holds "
             "no answer; cite the read), unreadable (the read failed; cite it) or out_of_scope (the "
             "brief excludes it)")


def _limitation_refusal(case_dir, part: dict[str, Any], basis: str, reason: str,
                        call_ids: list) -> Optional[str]:
    """Why a limitation cannot be recorded: a basis outside the set, a reason
    too short to state anything, an absent source the case holds, an
    examination without a successful read of the source, an unreadable
    source without a failed read, or an exclusion the brief does not make."""
    from core.request_parts import LIMITATION_BASES
    if basis not in LIMITATION_BASES:
        return f"limitation basis must be one of {', '.join(LIMITATION_BASES)}, not {basis!r}"
    reason = str(reason or "").strip()
    if len(reason) < 20:
        return "a limitation needs a reason of at least 20 characters naming the source and what was done"
    try:
        from core.entities import artifact_tokens
        named = {t.lower() for t in artifact_tokens(reason)}
    except Exception:  # noqa: BLE001
        named = set()
    named |= {w.lower().strip("'\"`,.;:()") for w in reason.split()
              if re.match(r"^\$?[A-Za-z][\w.$-]{2,}$", w.strip("'\"`,.;:()")) and w.strip("'\"`,.;:()").upper() == w.strip("'\"`,.;:()")}
    if basis == "source_absent":
        try:
            from core.artifact_value import known_artifacts
            known = known_artifacts(case_dir)
        except Exception:  # noqa: BLE001
            known = {}
        for v in known.values():
            base = str(v.get("name") or "").lower()
            stem = base.rsplit(".", 1)[0]
            if base in named or stem in named:
                where = v.get("lpath") or v.get("path") or v.get("name")
                return (f"'{where}' is present in this case (see the listing or path it was seen in); "
                        "a source the case holds cannot be called absent: examine it and limit the "
                        "part on what the examination gave, or answer it")
        return None
    if basis == "out_of_scope":
        try:
            brief = read_case_markdown(case_dir)
        except Exception:  # noqa: BLE001
            brief = ""
        if not re.search(r"(?i)out of scope|not (?:part of|in) (?:the )?scope|excluded|ausgenommen|nicht (?:teil|gegenstand)", brief or ""):
            return "out_of_scope needs the brief to exclude the source (a phrase such as 'out of scope' or 'excluded')"
        return None
    # examined / unreadable: the cited calls must be reads of the source
    ids = [int(c) for c in call_ids if str(c).strip().isdigit()]
    if not ids:
        return f"{basis} needs call_ids: the call(s) that read (or failed to read) the source"
    try:
        from core.execution_log import log
        by = log.index().by_call_id or {}
    except Exception:  # noqa: BLE001
        by = {}
    try:
        from core.coverage_ledger import reads_content
    except Exception:  # noqa: BLE001
        reads_content = lambda name: True  # noqa: E731
    seen_any = False
    for cid in ids:
        ent = by.get(cid) or by.get(str(cid)) or {}
        if not ent:
            continue
        seen_any = True
        blob = json.dumps(ent, ensure_ascii=False).lower()
        names_source = not named or any(n in blob for n in named)
        tool = str(ent.get("mcp_tool") or ent.get("tool") or ent.get("cmd") or "").split(":")[-1]
        ok = bool(ent.get("success"))
        if basis == "examined" and ok and reads_content(tool) and names_source:
            return None
        if basis == "unreadable" and not ok and names_source:
            return None
    if not seen_any:
        return f"none of the cited call ids {ids} is in this run's trace"
    if basis == "examined":
        return ("examined needs a successful reader call on the source (a parse, query or read that "
                "names it); a listing or a stat that merely names the path does not count")
    return "unreadable needs a failed call on the source among the cited call ids"


def update_task(
    case_dir: str | os.PathLike,
    task_id: str,
    *,
    status: Optional[str] = None,
    related_claim_ids: Optional[list[str]] = None,
    parts: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Update one task's status, related claim ids and/or parts. Persists.

    ``parts`` maps part ids to ``{"claim_ids": [...]}`` (the beliefs that
    answer the part, tested for a value of the part's kind) or
    ``{"limitation": {"basis", "reason", "call_ids"}}``. A task with parts
    takes its status from them: ``answered`` is refused while a part is
    open, and ``blocked_missing_evidence`` while a part is neither answered
    nor limited.
    """
    store = load_tasks(case_dir)
    found = None
    for t in store.get("tasks") or []:
        if t.get("id") == task_id:
            found = t
            break
    if found is None:
        return {"success": False, "error": f"unknown task id: {task_id}"}
    if status is not None:
        status = normalize_task_status(status)
        if status not in TASK_STATUSES:
            return {"success": False, "error": f"invalid status: {status}"}
        if status == "blocked_missing_evidence":
            refuse = _disk_access_blocks_missing_evidence(
                case_dir, str(found.get("text") or ""),
            )
            if refuse:
                return {
                    "success": False,
                    "gate": "task_status_contract",
                    "error": refuse,
                }
        if status == "answered":
            try:
                from core.evidence_access import refuse_diskish_answered
                refuse_ans = refuse_diskish_answered(
                    case_dir, str(found.get("text") or ""),
                )
            except Exception:
                refuse_ans = None
            if refuse_ans:
                return {
                    "success": False,
                    "gate": "task_status_contract",
                    "error": refuse_ans,
                }
            try:
                from core.coverage_ledger import refuse_answered_unseen_coverage
                refuse_cov = refuse_answered_unseen_coverage(
                    case_dir,
                    str(found.get("text") or ""),
                    task_id=str(found.get("id") or task_id),
                )
            except Exception:
                refuse_cov = None
            if refuse_cov:
                return {
                    "success": False,
                    "gate": "task_coverage_disposition",
                    "error": refuse_cov,
                }
        if status in ("answered", "partial"):
            # A question is answered *by* something. The dashboard, the
            # report's answers section and the finish classification all
            # derive the answer from the linked beliefs — a task marked
            # answered with none is a green tick over nothing ("Marked
            # answered, but no linked claims were found").
            from core.request_parts import open_parts as _open_parts
            proposed = (related_claim_ids if related_claim_ids is not None
                        else found.get("related_claim_ids") or [])
            if not active_support(case_dir, proposed):
                offered = answer_candidates(case_dir, parts=_open_parts(found))
                return {
                    "success": False,
                    "gate": "task_answer_unsupported",
                    "error": (
                        f"{status!r} needs the belief(s) that answer it: pass "
                        "related_claim_ids=[...] naming current claim, "
                        "conclusion or observation ids (record the finding first, or "
                        "claim.promote_conclusion the one that states the "
                        "answer). Nothing given resolves to an active belief."
                    ),
                    "candidates": offered,
                }
            # And the belief has to be *about* the question: one claim does
            # not close several questions that ask about different things.
            # An umbrella question ("what happened?") is answered by anything.
            unrelated = _unrelated_support(case_dir, str(found.get("text") or ""), proposed)
            if unrelated is not None and found.get("parts"):
                # A belief that answers a part of the request is related to
                # it whatever vocabulary the other parts use.
                from core.request_parts import assign as _assign
                probe = {"text": found.get("text"), "parts": json.loads(json.dumps(found.get("parts")))}
                if _assign(probe, _graph_nodes(case_dir), proposed, known_hosts=_known_hosts(case_dir), lenient=True):
                    unrelated = None
            if unrelated is not None:
                return {
                    "success": False,
                    "gate": "task_answer_unrelated",
                    "error": (
                        f"{status!r} needs a belief that speaks to this question. "
                        f"None of {unrelated} shares anything with "
                        f"{str(found.get('text') or '')[:80]!r} — link the claim that "
                        "does (or record it first), or keep the task open."
                    ),
                    "candidates": answer_candidates(case_dir, parts=_open_parts(found)),
                }
        found["status"] = status
    if related_claim_ids is not None:
        found["related_claim_ids"] = list(dict.fromkeys(related_claim_ids))
    task_parts = [p for p in (found.get("parts") or []) if isinstance(p, dict)]
    if task_parts:
        from core.request_parts import assign, derive_status, limit, open_parts, summary_lines
        nodes = _graph_nodes(case_dir)
        hosts = _known_hosts(case_dir)
        from core.request_parts import LIMITATION_BASES, STRICT_VALUE_TYPES, _current, part_words
        by_id = {str(p.get("id")): p for p in task_parts}
        by_text = {str(p.get("text") or "").strip().casefold(): p for p in task_parts}
        notes: list[str] = []
        for pid, spec in (parts or {}).items():
            part = by_id.get(str(pid)) or by_text.get(str(pid).strip().casefold()) or next(
                (p for p in task_parts if str(pid).strip().casefold() in str(p.get("text") or "").casefold()), None)
            if part is None:
                return {"success": False, "error": f"unknown part {pid!r}; parts: "
                        + ", ".join(f"{p['id']} {p['text']}" for p in task_parts)}
            if not isinstance(spec, dict):
                return {"success": False, "error": (
                    f"part {pid!r} takes an object, not {type(spec).__name__}; {PARTS_HOW}. "
                    "A value written here is not evidence")}
            pid = str(part.get("id"))
            if "basis" in spec and "limitation" not in spec:
                # The limitation's fields given flat under the part.
                spec = {"limitation": {k: spec.get(k) for k in ("basis", "reason", "call_ids")}}
            if isinstance(spec.get("claim_ids"), str):
                spec = {**spec, "claim_ids": [spec["claim_ids"]]}
            lim_spec = spec.get("limitation") if isinstance(spec.get("limitation"), dict) else None
            if lim_spec and not spec.get("claim_ids"):
                # Belief ids where a limitation's basis belongs: the model
                # pointed at the belief that covers the part. Only live beliefs
                # of the graph count; anything else is refused as a basis.
                basis_text = str(lim_spec.get("basis") or "").strip()
                if basis_text not in LIMITATION_BASES:
                    live = [str(n.get("id")) for n in _current(nodes, [b for b in re.split(r"[\s,;]+", basis_text) if b])]
                    if live:
                        spec = {"claim_ids": live}
                        notes.append(f"{pid}: the limitation's basis named {', '.join(live)}, read as the part's link")
            if spec.get("claim_ids"):
                ids = [str(c) for c in spec["claim_ids"] if c]
                part["status"] = "open"
                assign(found, nodes, ids, known_hosts=hosts, explicit={str(pid): ids}, lenient=True)
                if part.get("status") != "answered":
                    from core.answer_values import VALUE_TYPES, explicit_candidates
                    from core.request_parts import _typed_values
                    typ = str(part.get("type") or "")
                    # A belief that states several values of the kind, none
                    # beside the part's words: which one is meant is the
                    # analyst's call, not the first one's.
                    stated = list(dict.fromkeys(
                        v for n in _current(nodes, ids)
                        for v in explicit_candidates(str(part.get("text") or ""), typ, str(n.get("statement") or ""),
                                                     question=str(found.get("text") or ""), known_hosts=hosts,
                                                     prefer=_typed_values(n, typ))
                    )) if part.get("kind") == "value" and typ in VALUE_TYPES and part.get("typed_by") != "default" else []
                    if len(stated) > 1:
                        typed = {v.lower() for n in _current(nodes, ids) for v in _typed_values(n, typ)}
                        # Typing helps only while one of them is untyped.
                        how = ("each of them is already typed on the belief, so link a belief whose clause "
                               "names the part beside its value, or limit the part"
                               if all(v.lower() in typed for v in stated) else
                               "type the one meant on its belief with claim.add_indicators(claim_id, "
                               "[{type, value, side}]) and link it again, link a belief whose clause names "
                               "the part beside its value, or limit the part")
                        return {"success": False, "gate": "task_part_unsupported",
                                "error": (f"part {pid} ({part.get('text')!r}) is not answered by {ids}: "
                                          f"{'it states' if len(ids) == 1 else 'they state'} "
                                          f"{len(stated)} {typ} values ({', '.join(stated[:6])}) and no clause names "
                                          "the part's words beside one, so which one it asks for is not stated: "
                                          f"{how}; {PARTS_HOW}"),
                                "parts": summary_lines(found)}
                    if part.get("kind") == "relation":
                        need = "a stated relation naming a term from each side"
                    elif str(part.get("type")) in STRICT_VALUE_TYPES:
                        need = (f"a {part.get('type')} value, which a link answers only through "
                                "a belief that states it")
                    else:
                        words = ", ".join(sorted(part_words(str(part.get("text") or "")))) or "its words"
                        need = (f"what the part asks about ({words}) in a statement that is not a gap "
                                f"or an absence, nor a {part.get('type')} value")
                    return {"success": False, "gate": "task_part_unsupported",
                            "error": (f"part {pid} ({part.get('text')!r}) is not answered by {ids}: "
                                      f"none of them carries {need}. Link the belief that does, limit "
                                      f"the part, or record the belief that states it first; when that "
                                      f"belief sharpens one of {ids}, record it with supersedes=<that "
                                      f"id>, which replaces it instead of adding a variant beside it; "
                                      f"{PARTS_HOW}"),
                            "parts": summary_lines(found)}
            elif spec.get("limitation"):
                lim = spec["limitation"] if isinstance(spec["limitation"], dict) else {}
                refuse = _limitation_refusal(case_dir, part, str(lim.get("basis") or ""),
                                             str(lim.get("reason") or ""), list(lim.get("call_ids") or []))
                if refuse:
                    return {"success": False, "gate": "task_part_limitation", "error": refuse,
                            "parts": summary_lines(found)}
                limit(part, str(lim.get("basis")), str(lim.get("reason")), list(lim.get("call_ids") or []))
        # The linked beliefs answer what they can, by the typed test; a
        # host answered "not affected" closes its standard parts.
        from core.request_parts import close_unaffected_hosts
        assign(found, nodes, found.get("related_claim_ids") or [], known_hosts=hosts, lenient=True)
        close_unaffected_hosts(found, nodes)
        derived = derive_status(found, keep_markers=False)
        if status in ("answered", "blocked_missing_evidence") and derived != status:
            pending = open_parts(found)
            return {"success": False, "gate": "task_parts_open",
                    "error": (f"{status!r} needs every part answered or limited; open: "
                              + "; ".join(f"{p['id']} {p['text']} (needs a value of kind {p['type']})" for p in pending)
                              + ". Link the belief that answers each open part (it is accepted when it "
                              "carries what the part asks about, even where no value can be read from "
                              "it; an ip, mac, email, hash or domain part needs a belief that states "
                              "the value), limit a part the evidence cannot answer, or record the belief "
                              f"that states it first; {PARTS_HOW}"),
                    "parts": summary_lines(found), "candidates": answer_candidates(case_dir, parts=pending)}
        found["status"] = derived
    found["updated_at"] = _utcnow()
    save_tasks(case_dir, store)
    out: dict[str, Any] = {"success": True, "task": found}
    if task_parts:
        out["parts"] = summary_lines(found)
        if notes:
            out["notes"] = notes
    hint = _synthesis_hint(case_dir, found)
    if hint:
        out["synthesis_hint"] = hint
    shape = _answer_shape_hint(case_dir, found)
    if shape:
        out["answer_shape"] = shape
    return out


_SHAPE_HINTS = {
    "count": ("the question asks for a number and the linked beliefs state none: "
              "record the count (a finding, or claim.promote_conclusion naming it) "
              "and link it here"),
    "named": ("the question asks which items and the linked beliefs name none: "
              "state the file names, addresses or identifiers (a conclusion listing "
              "them) and link it here"),
}


def _answer_shape_hint(case_dir, task: dict[str, Any]) -> Optional[str]:
    """An answered question whose linked beliefs lack the shape it asks for
    (a count without a number, nameable items without a name) is told so.
    Advisory: the answer stands either way."""
    if task.get("status") not in ("answered", "partial"):
        return None
    ids = [str(c) for c in (task.get("related_claim_ids") or [])]
    if not ids:
        return None
    try:
        from core.claim_graph import load_graph
        nodes = load_graph(case_dir).get("nodes") or {}
    except Exception:  # noqa: BLE001
        return None
    statements = [str((nodes.get(c) or {}).get("statement") or "") for c in ids]
    try:
        from core.case_config import get_report_language
        language = get_report_language(case_dir)
    except Exception:  # noqa: BLE001
        language = "en"
    from core.answer_synthesis import answer_shape_gap
    return _SHAPE_HINTS.get(answer_shape_gap(str(task.get("text") or ""), statements, language))


def _synthesis_hint(case_dir, task: dict[str, Any]) -> Optional[str]:
    """An answer that rests on individual claims only, with no conclusion
    among them, is told how to become one statement. Advisory: the answer
    stands either way."""
    if task.get("status") not in ("answered", "partial"):
        return None
    ids = [str(c) for c in (task.get("related_claim_ids") or [])]
    if not ids:
        return None
    try:
        from core.claim_graph import load_graph
        nodes = load_graph(case_dir).get("nodes") or {}
    except Exception:  # noqa: BLE001
        return None
    if any((nodes.get(c) or {}).get("kind") == "conclusion" for c in ids):
        return None
    return (
        "The answer rests on individual claims. claim.promote_conclusion "
        "records the one statement that answers this question with these "
        "claims as its support, so the report's answer reads as a conclusion "
        "rather than a list of observations; then link the conclusion id here."
    )


def _unrelated_support(case_dir, task_text: str, claim_ids) -> Optional[list[str]]:
    """The ids given when none of them relates to the question; None when
    at least one does (or the question is general)."""
    ids = [str(c) for c in (claim_ids or []) if c]
    if not ids:
        return None
    try:
        from core.answer_synthesis import is_general_question
        if is_general_question(task_text):
            return None
    except Exception:  # noqa: BLE001
        pass
    try:
        from core.claim_graph import load_graph
        nodes = load_graph(case_dir).get("nodes") or {}
    except Exception:  # noqa: BLE001
        return None
    from core.answer_synthesis import speaks_to
    related = [cid for cid in ids if cid in nodes and speaks_to(
        task_text, str(nodes[cid].get("statement") or ""), str(nodes[cid].get("host") or ""))]
    return None if related or not any(c in nodes for c in ids) else ids


def repair_unsupported_answers(case_dir: str | os.PathLike) -> list[str]:
    """Reopen tasks marked answered/partial that no current belief supports.

    Runs at close-out. The contract in ``update_task`` prevents new cases of
    this; the repair covers stores written before it existed and beliefs
    that were later withdrawn. Returns the ids it reopened.
    """
    if not tasks_path(case_dir).is_file():
        return []
    store = load_tasks(case_dir)
    reopened: list[str] = []
    nodes = _graph_nodes(case_dir)
    parts_changed = False
    for t in store.get("tasks") or []:
        if isinstance(t, dict) and t.get("parts"):
            from core.request_parts import clear_gone, derive_status
            if clear_gone(t, nodes):
                parts_changed = True
            new_status = derive_status(t)
            if new_status != t.get("status"):
                t["status"] = new_status
                t["updated_at"] = _utcnow()
                parts_changed = True
    for t in store.get("tasks") or []:
        if not isinstance(t, dict) or t.get("status") not in ("answered", "partial"):
            continue
        if active_support(case_dir, t.get("related_claim_ids")):
            continue
        t["status"] = "reopened"
        t["note"] = ("reopened at close-out: marked "
                     f"{t.get('status', 'answered')} without any current "
                     "supporting belief")
        t["updated_at"] = _utcnow()
        reopened.append(str(t.get("id")))
    if reopened or parts_changed:
        save_tasks(case_dir, store)
    return reopened


def supersede_task(
    case_dir: str | os.PathLike,
    old_task_id: str,
    new_task_id: str,
) -> dict[str, Any]:
    """Explicitly mark ``old_task_id`` as dropped in favor of ``new_task_id``.

    Never called by fuzzy/similarity logic — reconcile only drops inbox lines
    that disappeared from CASE.md without inventing ``superseded_by`` links.
    """
    if not old_task_id or not new_task_id:
        return {"success": False, "error": "old_task_id and new_task_id required"}
    if old_task_id == new_task_id:
        return {"success": False, "error": "cannot supersede a task with itself"}
    store = load_tasks(case_dir)
    by_id = {t.get("id"): t for t in (store.get("tasks") or []) if isinstance(t, dict)}
    old = by_id.get(old_task_id)
    new = by_id.get(new_task_id)
    if old is None:
        return {"success": False, "error": f"unknown task id: {old_task_id}"}
    if new is None:
        return {"success": False, "error": f"unknown task id: {new_task_id}"}
    old["status"] = "dropped"
    old["superseded_by"] = new_task_id
    old["updated_at"] = _utcnow()
    save_tasks(case_dir, store)
    return {"success": True, "task": old, "superseded_by": new_task_id}


def add_derived_task(
    case_dir: str | os.PathLike,
    text: str,
    *,
    related_claim_ids: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Create a system-derived revisit task (exact-text dedupe only).

    Applies DERIVED_PREFIX here rather than trusting each caller: the prefix is
    what stops reconcile_case_md from dropping the task, and only
    core/derived_revisit.py used to set it.
    """
    text = (text or "").strip()
    if not text:
        return {"success": False, "error": "empty derived task text"}
    if not text.lstrip().lower().startswith(DERIVED_PREFIX):
        text = f"{DERIVED_PREFIX} {text}"
    store = load_tasks(case_dir)
    fp = fingerprint_text(text)
    for t in store.get("tasks") or []:
        if fingerprint_text(t.get("text") or "") == fp:
            return {"success": True, "task": t, "created": False}
    task = _make_task(store, text, status="open")
    if related_claim_ids:
        task["related_claim_ids"] = list(dict.fromkeys(related_claim_ids))
    store.setdefault("tasks", []).append(task)
    save_tasks(case_dir, store)
    return {"success": True, "task": task, "created": True}


def reopen_tasks_for_claims(
    case_dir: str | os.PathLike,
    claim_ids: list[str],
) -> dict[str, Any]:
    """Set answered tasks linked to claim_ids → reopened."""
    if not claim_ids:
        return {"reopened": [], "skipped": []}
    want = set(claim_ids)
    store = load_tasks(case_dir)
    reopened: list[str] = []
    skipped: list[str] = []
    now = _utcnow()
    for t in store.get("tasks") or []:
        related = set(t.get("related_claim_ids") or [])
        if not related & want:
            continue
        if t.get("status") == "answered":
            t["status"] = "reopened"
            t["updated_at"] = now
            reopened.append(t["id"])
        else:
            skipped.append(t.get("id") or "")
    if reopened:
        save_tasks(case_dir, store)
    return {"reopened": reopened, "skipped": skipped}


def restore_tasks_for_claims(
    case_dir: str | os.PathLike,
    claim_ids: list[str],
    current_ids: set[str] | frozenset[str],
    gone_ids: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """The mirror of ``reopen_tasks_for_claims``: a task reopened because a
    belief it rests on went under review is answered again once every
    belief it rests on is current. ``current_ids`` are the graph's current
    beliefs; ``gone_ids`` the superseded and withdrawn ones, which a task
    keeps in its links by design and which hold nothing open; a task
    linked to a belief still under review stays reopened."""
    if not claim_ids or not tasks_path(case_dir).is_file():
        return {"restored": [], "skipped": []}
    want = set(claim_ids)
    store = load_tasks(case_dir)
    restored: list[str] = []
    skipped: list[str] = []
    now = _utcnow()
    for t in store.get("tasks") or []:
        related = set(t.get("related_claim_ids") or [])
        if not related & want or t.get("status") != "reopened":
            continue
        live = related - set(gone_ids)
        if live and live <= set(current_ids):
            t["status"] = "answered"
            t["updated_at"] = now
            restored.append(t["id"])
        else:
            skipped.append(t.get("id") or "")
    if restored:
        save_tasks(case_dir, store)
    return {"restored": restored, "skipped": skipped}


def carry_links_on_supersede(case_dir: str | os.PathLike, old_id: str,
                             new_id: str) -> list[str]:
    """A task answered by a belief stays answered by the belief that
    replaces it: every task linked to ``old_id`` gains ``new_id``. The old
    id stays for the record; the answer projection skips gone beliefs.
    Returns the ids of the tasks changed."""
    if not old_id or not new_id or old_id == new_id or not tasks_path(case_dir).is_file():
        return []
    store = load_tasks(case_dir)
    changed: list[str] = []
    now = _utcnow()
    nodes = _graph_nodes(case_dir)
    hosts = _known_hosts(case_dir)
    for t in store.get("tasks") or []:
        if not isinstance(t, dict):
            continue
        related = [str(c) for c in (t.get("related_claim_ids") or [])]
        if old_id in related and new_id not in related:
            related.append(new_id)
            t["related_claim_ids"] = related
            t["updated_at"] = now
            changed.append(str(t.get("id")))
        if t.get("parts"):
            from core.request_parts import carry, derive_status
            if carry(t, old_id, new_id, nodes, known_hosts=hosts):
                t["status"] = derive_status(t)
                t["updated_at"] = now
                if str(t.get("id")) not in changed:
                    changed.append(str(t.get("id")))
    if changed:
        save_tasks(case_dir, store)
    return changed


# Token glue for finding→task auto-link (not task-text fuzzy merge).
_LINK_STOPWORDS = frozenset({
    "the", "and", "for", "with", "from", "that", "this", "into", "onto",
    "was", "were", "are", "been", "being", "have", "has", "had", "not",
    "any", "all", "via", "per", "over", "under", "about", "after", "before",
    "investigate", "determine", "whether", "check", "find", "review",
    "analyze", "analyse", "confirm", "identify", "evidence", "activity",
    "event", "events", "host", "user", "system", "file", "files", "log",
    "logs", "case", "question", "request", "please", "what", "when", "where",
    "which", "who", "how", "did", "does", "there", "their", "them",
})


def link_tokens(text: str) -> set[str]:
    """Tokenize text for task↔finding / task↔path soft matching."""
    toks = set(re.findall(r"[a-z0-9][a-z0-9._-]{2,}", (text or "").casefold()))
    return {t.strip("._-") for t in toks if t.strip("._-") not in _LINK_STOPWORDS}


# Back-compat alias used by earlier call sites during the S4 wave.
_link_tokens = link_tokens


def _task_link_score(task_text: str, statement: str, host: str = "") -> float:
    """Overlap score between an inbox task and a recorded finding statement."""
    task_toks = link_tokens(task_text)
    stmt_toks = link_tokens(statement) | link_tokens(host)
    if not task_toks or not stmt_toks:
        return 0.0
    overlap = task_toks & stmt_toks
    if not overlap:
        return 0.0
    # Prefer distinctive tokens (hostnames, accounts, technique-ish ids).
    weight = sum(2.0 if len(t) >= 6 else 1.0 for t in overlap)
    return weight


def link_claim_to_tasks(
    case_dir: str | os.PathLike,
    claim_id: str,
    *,
    statement: str = "",
    host: str = "",
    persist: bool = True,
) -> dict[str, Any]:
    """Attach a claim_id to matching actionable tasks (auto progress link).

    Matching is token-overlap on task text vs finding statement/host — not a
    fuzzy merge of inbox wording. Sole open inbox task always receives the
    claim (single-question cases). Does **not** mark tasks answered; bumps
    ``open`` → ``in_progress`` when a claim lands.
    """
    if not claim_id:
        return {"linked": [], "skipped": True, "reason": "empty_claim_id"}
    if not tasks_path(case_dir).is_file():
        return {"linked": [], "skipped": True, "reason": "no_task_store"}

    store = load_tasks(case_dir)
    actionable = [
        t for t in (store.get("tasks") or [])
        if isinstance(t, dict) and t.get("status") in _ACTIONABLE
    ]
    if not actionable:
        return {"linked": [], "skipped": True, "reason": "no_actionable_tasks"}

    # A link means "this belief helps answer that question": the same rule
    # the report's answers use. Word overlap alone links a note about a log's
    # format to an exfiltration question, or a bare count to "what type of
    # attack", and the report then answers with them.
    try:
        from core.answer_synthesis import _shares_act, lead_sentence, speaks_to
    except Exception:  # noqa: BLE001
        _shares_act = lambda q, s: False  # noqa: E731
        lead_sentence = lambda s: str(s or "")  # noqa: E731
        speaks_to = lambda q, s, h="", strict=False: True  # noqa: E731
    scored: list[tuple[float, dict[str, Any]]] = []
    lead = lead_sentence(statement)
    for t in actionable:
        text = str(t.get("text") or "")
        sc = _task_link_score(text, lead, host)      # overlap in the assertion, not in a caveat
        # the subject must agree (a VPN question is not answered by an RDP
        # logon just because both are authentications), and then either the
        # act or a distinctive shared word in the assertion itself
        if speaks_to(text, statement, host, strict=True) and (_shares_act(text, lead) or sc >= 2.0):
            scored.append((max(sc, 2.0), t))
    if not scored and len(actionable) == 1:
        scored = [(1.0, actionable[0])]

    linked: list[str] = []
    now = _utcnow()
    nodes: dict[str, dict] | None = None
    for _sc, t in scored:
        related = list(t.get("related_claim_ids") or [])
        if claim_id not in related:
            related.append(claim_id)
            t["related_claim_ids"] = related
            linked.append(str(t.get("id")))
        if t.get("status") == "open":
            t["status"] = "in_progress"
        if t.get("parts"):
            from core.request_parts import assign, derive_status
            if nodes is None:
                nodes = _graph_nodes(case_dir)
                if claim_id not in nodes and statement:
                    nodes[claim_id] = {"id": claim_id, "kind": "claim", "status": "new",
                                       "statement": statement, "host": host}
            assign(t, nodes, [claim_id], known_hosts=_known_hosts(case_dir))
            t["status"] = derive_status(t)
        t["updated_at"] = now

    if linked and persist:
        save_tasks(case_dir, store)
    return {
        "linked": linked,
        "skipped": not linked,
        "candidates_scored": len(scored),
    }


def reconcile_case_md(
    case_dir: str | os.PathLike,
    *,
    persist: bool = True,
    case_id: str = "",
) -> dict[str, Any]:
    """Reconcile CASE.md investigation requests with the task store.

    Deterministic exact-match only. Different wording → new task.
    """
    root = Path(case_dir).resolve()
    md = read_case_markdown(root)
    items = parse_case_request_items(md)
    requests = [item["text"] for item in items]
    children_of = {item["text"]: list(item.get("children") or []) for item in items}
    # The request's first physical line is what an earlier reader stored:
    # a task written that way is the same request, cut short.
    first_line_of = {item["text"]: item["first_line"] for item in items
                     if item.get("first_line") and item["first_line"] != item["text"]}
    store = load_tasks(root)
    # Persist only when the store actually changes. Every dashboard read
    # reconciles, and rewriting an identical store on each read is not just
    # waste: with a change feed announcing writes to the pages that read,
    # it is a loop.
    changed = not tasks_path(root).is_file()
    if case_id:
        if store.get("case_id") != case_id:
            store["case_id"] = case_id
            changed = True
    elif not store.get("case_id"):
        store["case_id"] = root.name
        changed = True

    # Index existing non-dropped tasks by fingerprint (first wins).
    by_fp: dict[str, dict[str, Any]] = {}
    for t in store.get("tasks") or []:
        if t.get("status") == "dropped":
            continue
        fp = fingerprint_text(t.get("text") or "")
        if fp and fp not in by_fp:
            by_fp[fp] = t

    seen_fps: set[str] = set()
    added: list[str] = []
    matched: list[str] = []
    now = _utcnow()

    extended: list[str] = []
    for text in requests:
        fp = fingerprint_text(text)
        if not fp:
            continue
        seen_fps.add(fp)
        existing = by_fp.get(fp)
        if existing is None and text in first_line_of:
            short = by_fp.get(fingerprint_text(first_line_of[text]))
            if short is not None:
                # The stored task holds the request's first line only: it
                # takes the whole request. Its answer was earned against
                # the first line, so an answered or partial task reopens
                # with its beliefs kept as candidates.
                short["text"] = text
                if short.get("status") in ("answered", "partial"):
                    short["status"] = "reopened"
                    short["note"] = ("text extended; earlier answer covered its "
                                     "first line")
                short["updated_at"] = now
                by_fp[fp] = short
                extended.append(short["id"])
                changed = True
                existing = short
        if existing is not None:
            # Revive dropped-equivalent: if somehow matched a dropped task, reopen
            if existing.get("status") == "dropped":
                existing["status"] = "open"
                existing["updated_at"] = now
                changed = True
            matched.append(existing["id"])
        else:
            task = _make_task(store, text, status="open")
            store.setdefault("tasks", []).append(task)
            by_fp[fp] = task
            added.append(task["id"])
            changed = True

    # Every request has its parts (the deterministic split here; a writer
    # path may replace it with the model's), and its status follows them.
    from core.request_parts import assign, derive_status, ensure_parts, ensure_standard_parts
    computer_hosts: list[str] | None = None
    nodes: dict[str, dict] | None = None
    for t in store.get("tasks") or []:
        if not isinstance(t, dict) or t.get("status") == "dropped":
            continue
        fresh = ensure_parts(t, children_of.get(str(t.get("text") or "")))
        if fresh:
            changed = True
        if any(isinstance(p, dict) and p.get("kind") == "umbrella" for p in t.get("parts") or []):
            if computer_hosts is None:
                computer_hosts = _computer_hosts(root)
            if ensure_standard_parts(t, computer_hosts):
                changed = True
                fresh = True
        if fresh and t.get("related_claim_ids"):
            # Parts written for a task that already had its beliefs are
            # answered by them where they can be: a store written before
            # parts existed keeps the answers its beliefs carry.
            if nodes is None:
                nodes = _graph_nodes(root)
            assign(t, nodes, t.get("related_claim_ids") or [], known_hosts=_known_hosts(root),
                   lenient=t.get("status") in ("answered", "partial"))
        new_status = derive_status(t)
        if new_status != t.get("status"):
            t["status"] = new_status
            changed = True

    # A line removed from CASE.md drops its task. But "nothing parsed" is not
    # "every line was removed": an empty, absent, renamed-heading or prose-only
    # CASE.md yields zero requests, and dropping on that wipes the entire
    # actionable queue — in_progress tasks and their related_claim_ids included
    # — on the hot path of every run, with nothing said. Five of the nine
    # shipped case briefs parse to zero or to prose. So reconciliation only
    # removes work when the brief actually produced work to compare against.
    dropped: list[str] = []
    # An unclosed fenced block hides every request after it: what parsed is
    # then not the brief, and dropping on it would remove the hidden requests'
    # tasks with their claim links. A request removed for real lingers until
    # the block is closed, the cheaper error.
    fence = unclosed_fence(md)
    drops_skipped = bool(requests and fence)
    if drops_skipped:
        import logging
        logging.getLogger(__name__).warning(
            "reconcile_case_md: CASE.md under %s opens a fenced block at line %s "
            "that never closes; no task dropped until it is closed.",
            root, fence["line"],
        )
    elif requests:
        for t in store.get("tasks") or []:
            fp = fingerprint_text(t.get("text") or "")
            if fp in seen_fps or t.get("status") not in _DROPPABLE:
                continue
            # Derived revisit texts are not CASE.md lines, so their absence from
            # the brief is not a removal. add_derived_task guarantees the marker.
            if (t.get("text") or "").lstrip().lower().startswith(DERIVED_PREFIX):
                continue
            t["status"] = "dropped"
            t["updated_at"] = now
            dropped.append(t["id"])
            changed = True
    elif any(t.get("status") in _DROPPABLE for t in store.get("tasks") or []):
        import logging
        logging.getLogger(__name__).warning(
            "reconcile_case_md: CASE.md under %s yielded no investigation "
            "requests; leaving the existing task queue untouched. Put bullets "
            "under '## Investigation Requests' if work should be reconciled.",
            root,
        )

    if persist and changed:
        save_tasks(root, store)

    # Access-stage repair: staged disk cannot remain blocked_missing_evidence.
    repaired: list[str] = []
    try:
        fix = repair_tasks_against_access(root, persist=persist)
        repaired = list(fix.get("repaired") or [])
        if repaired:
            store = load_tasks(root)
    except Exception:
        pass

    return {
        "success": True,
        "requests_parsed": len(requests),
        "added": added,
        "extended": extended,
        "matched": matched,
        "dropped": dropped,
        "withdrawn": dropped,  # deprecated alias (task status is "dropped")
        "unclosed_fence": fence,
        "drops_skipped": drops_skipped,
        "repaired_access": repaired,
        "tasks": list(store.get("tasks") or []),
        "counts": {
            "total": len(store.get("tasks") or []),
            "added": len(added),
            "matched": len(matched),
            "dropped": len(dropped),
            "withdrawn": len(dropped),
            "actionable": sum(
                1 for t in (store.get("tasks") or [])
                if t.get("status") in _ACTIONABLE
            ),
        },
    }
