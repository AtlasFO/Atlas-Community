"""Case creation, deletion, and move for the dashboard Config Page and
new-case flow.

ID validation mirrors tools/monitor.py's `_case_dir` (reject empty/`/`/`..`)
restricted further to core.paths.parse_case_id_from_text's character class
(`[A-Za-z0-9_-]+`) so a dashboard-created case ID always round-trips through
CASE.md parsing safely — the same guarantee dashboard/serve.py's
`_safe_case_dir` already enforces on the read side.

Delete/move reuse tools/atlas_reset.py's two safety guarantees rather than
reinventing them: (1) refuse if anything is still mounted under the case
directory (core.mounts.unmount_all_under), and (2) never hard-delete by
default — move into a timestamped, recoverable location instead. Unlike
atlas_reset.py (which only ever clears run *state* under an existing case),
this module operates on the case directory itself, so there's no ready-made
function here to call — it's new code following that established pattern.
"""
from __future__ import annotations

import datetime
import re
import shutil
from pathlib import Path
from typing import Optional

from core.investigation_tasks import reconcile_case_md
from core.mounts import unmount_all_under

_CASE_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_CASE_ID_LEN = 100
_REPO_ROOT = Path(__file__).resolve().parents[1]
_CASE_TEMPLATE = _REPO_ROOT / "case-template"


class CaseAdminError(Exception):
    """Raised for validation/precondition failures — safe to show the admin."""


def _sync_tasks(case_dir: Path, case_id: str) -> None:
    """Reconcile CASE.md's Investigation Requests into the task store right
    away, so the dashboard Questions tab reflects them immediately instead
    of only after `atlas run`/`rerun` (the only other caller of
    reconcile_case_md, in core/incremental.py). Best-effort: a case is
    still successfully created/saved even if this sync step trips."""
    try:
        reconcile_case_md(case_dir, case_id=case_id)
    except Exception:
        pass


def validate_case_id(case_id: str) -> Optional[str]:
    if not case_id:
        return "case ID is required"
    if "/" in case_id or "\\" in case_id or ".." in case_id:
        return "case ID may not contain path separators or '..'"
    if len(case_id) > _MAX_CASE_ID_LEN:
        return f"case ID must be {_MAX_CASE_ID_LEN} characters or fewer"
    if not _CASE_ID_RE.match(case_id):
        return "case ID must be letters, digits, underscore, or hyphen only"
    return None


def _case_dir(cases_root: str, case_id: str) -> Path:
    err = validate_case_id(case_id)
    if err:
        raise CaseAdminError(err)
    return Path(cases_root) / case_id


def create_case(cases_root: str, case_id: str,
                requests: Optional[list[str]] = None,
                language: str = "") -> Path:
    """Copies case-template/ to <cases_root>/<case_id>, substituting the
    <CASE_ID> placeholder in CASE.md. Refuses if the destination exists.

    `language` is the report language (en|de), persisted in the case's own
    config so the report and its recommendations are written in it; an
    empty value keeps the default. Checked before anything is copied, so a
    bad value refuses without leaving a half-made case behind.
    """
    from core.case_config import SUPPORTED_LANGUAGES, set_report_language
    language = (language or "").strip().lower()
    if language and language not in SUPPORTED_LANGUAGES:
        raise CaseAdminError(
            f"unsupported language {language!r} (one of "
            f"{', '.join(sorted(SUPPORTED_LANGUAGES))})")
    dest = _case_dir(cases_root, case_id)
    if dest.exists():
        raise CaseAdminError(f"a case named {case_id!r} already exists")
    if not _CASE_TEMPLATE.is_dir():
        raise CaseAdminError(f"case-template/ not found at {_CASE_TEMPLATE}")

    # The template is a skeleton; state Atlas writes while running (its own
    # .atlas/ profile, brain injection, bytecode caches) must not seed a case.
    shutil.copytree(_CASE_TEMPLATE, dest,
                    ignore=shutil.ignore_patterns(".atlas", "__pycache__", "*.pyc",
                                                  "brain_injection.json"))
    # A case always has these folders. The template carries them, but a
    # copy of Atlas built without empty folders (a container image leaves
    # out every evidence/ folder) must still give a whole case.
    for sub in ("evidence", "analysis", "exports", "reports"):
        (dest / sub).mkdir(exist_ok=True)

    case_md = dest / "CASE.md"
    if case_md.is_file():
        text = case_md.read_text(encoding="utf-8")
        text = text.replace("<CASE_ID>", case_id)
        if requests:
            bullets = "\n".join(f"- {r.strip()}" for r in requests if r.strip())
            if bullets:
                # A callable replacement is used deliberately: re.sub()
                # interprets backslash escapes (\1, \g<...>, \U, ...) in a
                # *string* replacement, so free-text investigation requests
                # containing a Windows path (C:\Users\admin) or similar
                # crashed this with `re.error: bad escape`. A function
                # replacement returns its string literally, no escape
                # processing — the fix is structural, not input-sanitizing.
                text = re.sub(
                    r"(## Investigation Requests\n)",
                    lambda m: m.group(1) + bullets + "\n", text, count=1)
        case_md.write_text(text, encoding="utf-8")
    _sync_tasks(dest, case_id)
    if language:
        set_report_language(dest, language)
    return dest


def _timestamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _refuse_if_running(case_dir: Path) -> None:
    """The dashboard never holds a case's run lock itself, so a held lock is
    always a live run (started here or from the command line)."""
    from core import run_lock
    if run_lock.is_locked(case_dir):
        raise CaseAdminError("refusing: a run is in progress for this case")


def _refuse_if_mounted(case_dir: Path) -> None:
    result = unmount_all_under(str(case_dir))
    if result.get("remaining"):
        raise CaseAdminError(
            "refusing: still mounted under this case: "
            + ", ".join(result["remaining"]))


def delete_case(cases_root: str, case_id: str, *, purge: bool = False) -> dict:
    """Default: moves the case directory to <cases_root>/.deleted/<id>-<ts>/
    (recoverable). purge=True hard-deletes instead. Either way, refuses if
    anything is still mounted under the case dir."""
    src = _case_dir(cases_root, case_id)
    if not src.is_dir():
        raise CaseAdminError(f"no such case: {case_id!r}")
    _refuse_if_running(src)
    _refuse_if_mounted(src)

    if purge:
        shutil.rmtree(src)
        return {"success": True, "action": "purged", "case_id": case_id}

    trash = Path(cases_root) / ".deleted"
    trash.mkdir(exist_ok=True)
    dest = trash / f"{case_id}-{_timestamp()}"
    shutil.move(str(src), str(dest))
    return {"success": True, "action": "moved_to_trash", "case_id": case_id,
            "location": str(dest)}


def read_case_md(cases_root: str, case_id: str) -> dict:
    """CASE.md content for the dashboard's view/edit panel. `exists=False`
    with empty content if the case has no CASE.md yet (shouldn't normally
    happen post-create_case, but a hand-made case directory can lack one)."""
    case_dir = _case_dir(cases_root, case_id)
    if not case_dir.is_dir():
        raise CaseAdminError(f"no such case: {case_id!r}")
    case_md = case_dir / "CASE.md"
    if not case_md.is_file():
        return {"exists": False, "content": ""}
    return {"exists": True, "content": case_md.read_text(encoding="utf-8")}


def write_case_md(cases_root: str, case_id: str, content: str) -> dict:
    """Overwrites CASE.md for `case_id` — the dashboard editor's save action.

    Unlike create_case's own CASE.md write (a fresh file with no concurrent
    reader yet), this can race an in-progress run reading the same file —
    write-to-temp-then-replace so a reader never sees a half-written file.
    """
    from core.investigation_tasks import write_case_markdown
    case_dir = _case_dir(cases_root, case_id)
    if not case_dir.is_dir():
        raise CaseAdminError(f"no such case: {case_id!r}")
    write_case_markdown(case_dir, content)
    _sync_tasks(case_dir, case_id)
    return {"success": True}


def append_to_brief(cases_root: str, case_id: str, *,
                    requests=(), facts=()) -> dict:
    """Append questions and facts to the case's brief, the same file the
    Brief tab edits, so a run started with them reads them from CASE.md
    like any other. A case without a brief yet gets the template's."""
    from core.case_autofill import append_requests, clean_bullets
    from core.case_knowledge import append_facts_text, facts_in
    from core.investigation_tasks import parse_case_requests, write_case_markdown

    case_dir = _case_dir(cases_root, case_id)
    if not case_dir.is_dir():
        raise CaseAdminError(f"no such case: {case_id!r}")
    case_md = case_dir / "CASE.md"
    if case_md.is_file():
        text = case_md.read_text(encoding="utf-8")
    else:
        template = _CASE_TEMPLATE / "CASE.md"
        text = (template.read_text(encoding="utf-8").replace("<CASE_ID>", case_id)
                if template.is_file()
                else f"# Case: {case_id}\n\n**Case ID:** {case_id}\n")
    before_requests = len(parse_case_requests(text))
    before_facts = len(facts_in(text))
    out = append_requests(text, clean_bullets(list(requests)))
    out = append_facts_text(out, list(facts))
    if out == text:
        return {"success": True, "requests_added": 0, "facts_added": 0}
    write_case_markdown(case_dir, out)
    _sync_tasks(case_dir, case_id)
    return {
        "success": True,
        "requests_added": len(parse_case_requests(out)) - before_requests,
        "facts_added": len(facts_in(out)) - before_facts,
    }


def move_case(cases_root: str, case_id: str, new_case_id: str) -> dict:
    """Renames a case directory in place, best-effort-updating the
    **Case ID:** line in CASE.md to match."""
    src = _case_dir(cases_root, case_id)
    dest = _case_dir(cases_root, new_case_id)
    if not src.is_dir():
        raise CaseAdminError(f"no such case: {case_id!r}")
    if dest.exists():
        raise CaseAdminError(f"a case named {new_case_id!r} already exists")
    _refuse_if_running(src)
    _refuse_if_mounted(src)

    shutil.move(str(src), str(dest))
    case_md = dest / "CASE.md"
    if case_md.is_file():
        text = case_md.read_text(encoding="utf-8")
        updated = re.sub(
            r"(\*\*Case ID:?\*\*[:\s|]+)" + re.escape(case_id) + r"\b",
            r"\1" + new_case_id, text)
        if updated != text:
            case_md.write_text(updated, encoding="utf-8")
    return {"success": True, "case_id": new_case_id, "previous_id": case_id}
