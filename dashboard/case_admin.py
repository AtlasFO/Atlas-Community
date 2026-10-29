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
import os
import re
import shutil
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from core.investigation_tasks import reconcile_case_md, unclosed_fence
from core.mounts import unmount_all_under

_CASE_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_CASE_ID_LEN = 100
_REPO_ROOT = Path(__file__).resolve().parents[1]
_CASE_TEMPLATE = _REPO_ROOT / "case-template"


class CaseAdminError(Exception):
    """Raised for validation/precondition failures — safe to show the admin."""


def _sync_tasks(case_dir: Path) -> None:
    """Reconcile CASE.md's Investigation Requests into the task store right
    away, so the dashboard Questions tab reflects them immediately instead
    of only after `atlas run`/`rerun` (the only other caller of
    reconcile_case_md, in core/incremental.py). Best-effort: a case is
    still successfully created/saved even if this sync step trips.

    The store's case id follows the rule a run uses (resolve_case_id: the
    brief's Case ID line, else the folder name). The dashboard names a case
    by its folder, and passing that would rewrite the id of every case whose
    brief names another one, until the next run wrote it back."""
    try:
        from core.incremental import resolve_case_id
        reconcile_case_md(case_dir, case_id=resolve_case_id(case_dir))
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
    _sync_tasks(dest)
    if language:
        set_report_language(dest, language)
    return dest


def _timestamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class PurgeIncomplete(CaseAdminError):
    """A purge moved the case out of the case list but could not remove it."""


def _refuse_if_busy(cases_root: str, case_id: str) -> None:
    """Refuse a delete or rename of a case with a live run before anything
    is touched: the unmount and the chat close that come next would pull a
    running investigation's evidence mounts and end its chat worker. The
    manager's lock is held only to read the reason; _while_idle checks again
    under the lock right before the folder moves."""
    from dashboard import run_manager
    with run_manager.MANAGER.held(cases_root, case_id) as busy:
        pass
    if busy:
        raise CaseAdminError("refusing: a run is in progress for this case")


@contextmanager
def _while_idle(cases_root: str, case_id: str):
    """Run the block with the run manager's lock held and the case idle: a
    run this dashboard just started counts from its spawn on (before the
    child takes the run lock), a run from the command line by its pid or
    its run lock, and no new start can slip in between the check and the
    folder change."""
    from dashboard import run_manager
    with run_manager.MANAGER.held(cases_root, case_id) as busy:
        if busy:
            raise CaseAdminError("refusing: a run is in progress for this case")
        yield


def _refuse_other_filesystem(case_dir: Path, cases_root: str) -> None:
    """The folder change under the run manager's lock must be a rename: a
    case folder on another filesystem than the cases root (its own mount)
    would be copied, evidence and all, while every status read waits."""
    if os.stat(case_dir).st_dev != os.stat(cases_root).st_dev:
        raise CaseAdminError("refusing: the case folder is on another filesystem "
                             "than the cases root; move it by hand")


def _rename(src: Path, dest: Path) -> None:
    try:
        os.rename(src, dest)
    except OSError as exc:
        raise CaseAdminError(f"could not move the case folder: {exc}") from exc


def _close_chat(case_id: str) -> None:
    """An Ask Atlas worker runs with the case folder as its working
    directory; it is ended before the folder moves."""
    from dashboard import chat
    chat.MANAGER.close_case(case_id)


def _refuse_if_mounted(case_dir: Path) -> None:
    result = unmount_all_under(str(case_dir))
    if result.get("remaining"):
        raise CaseAdminError(
            "refusing: still mounted under this case: "
            + ", ".join(result["remaining"]))


def delete_case(cases_root: str, case_id: str, *, purge: bool = False,
                on_committed=None) -> dict:
    """Default: moves the case directory to <cases_root>/.deleted/<id>-<ts>/
    (recoverable). purge=True removes it for good: renamed into .deleted/
    first (the case leaves the list at once and the long removal runs
    without any lock held), then deleted. Either way, refuses while a run
    is live or anything is still mounted under the case dir.

    `on_committed` is called once the case has left the case list (after
    the rename), the point a purge cannot be taken back: the caller records
    the deletion there, so a removal that fails half way is still on record."""
    src = _case_dir(cases_root, case_id)
    if not src.is_dir():
        raise CaseAdminError(f"no such case: {case_id!r}")
    _refuse_if_busy(cases_root, case_id)
    _refuse_other_filesystem(src, cases_root)
    _refuse_if_mounted(src)
    _close_chat(case_id)

    trash = Path(cases_root) / ".deleted"
    trash.mkdir(exist_ok=True)
    dest = trash / f"{case_id}-{_timestamp()}{'-purging' if purge else ''}"
    with _while_idle(cases_root, case_id):
        _rename(src, dest)
    if on_committed is not None:
        on_committed()
    if purge:
        try:
            shutil.rmtree(dest)
        except OSError as exc:
            raise PurgeIncomplete(
                f"the case was moved to .deleted/{dest.name}, but removing it failed: "
                f"{exc}; delete that folder by hand") from exc
        return {"success": True, "action": "purged", "case_id": case_id}
    return {"success": True, "action": "moved_to_trash", "case_id": case_id,
            "location": str(dest)}


def read_case_md(cases_root: str, case_id: str) -> dict:
    """The brief for the dashboard's view/edit panel: the file the writer
    replaces (CASE.md, else CLAUDE.md) and its version, which a save sends
    back. `exists=False` with empty content if the case has no brief yet
    (shouldn't normally happen post-create_case, but a hand-made case
    directory can lack one)."""
    from core.investigation_tasks import case_markdown_version, read_case_markdown
    case_dir = _case_dir(cases_root, case_id)
    if not case_dir.is_dir():
        raise CaseAdminError(f"no such case: {case_id!r}")
    exists = (case_dir / "CASE.md").is_file() or (case_dir / "CLAUDE.md").is_file()
    content = read_case_markdown(case_dir)
    return {"exists": exists, "content": content, "version": case_markdown_version(content),
            "unclosed_fence": unclosed_fence(content) if exists else None}


class BriefConflict(CaseAdminError):
    """The brief changed after the editor read it: carries what is there now."""

    def __init__(self, current: str, version: str):
        super().__init__("someone else saved the brief after you opened it")
        self.current = current
        self.version = version


def write_case_md(cases_root: str, case_id: str, content: str, version: str) -> dict:
    """Replaces the brief for `case_id` — the dashboard editor's save action.

    `version` is the version of the text the editor started from (read_case_md
    returned it). When the brief has changed since — another user's save, a
    question added in the start dialog, `atlas rerun -q` — nothing is written
    and BriefConflict carries the current text, so a stale tab never erases
    someone else's change. The write itself is the shared atomic replace, so
    a run reading the brief never sees half a file.
    """
    from core.investigation_tasks import CaseMarkdownConflict, write_case_markdown
    case_dir = _case_dir(cases_root, case_id)
    if not case_dir.is_dir():
        raise CaseAdminError(f"no such case: {case_id!r}")
    try:
        write_case_markdown(case_dir, content, base_version=version)
    except CaseMarkdownConflict as exc:
        raise BriefConflict(exc.current, exc.version) from exc
    _sync_tasks(case_dir)
    from core.investigation_tasks import case_markdown_version
    # A ``` line that never closes hides the rest of the brief from every
    # parser: the editor says so instead of a plain "Saved.".
    return {"success": True, "version": case_markdown_version(content),
            "unclosed_fence": unclosed_fence(content)}


def append_to_brief(cases_root: str, case_id: str, *,
                    requests=(), facts=()) -> dict:
    """Append questions and facts to the case's brief, the same file the
    Brief tab edits, so a run started with them reads them from CASE.md
    like any other. A case without a brief yet gets the template's."""
    from core.case_autofill import append_requests, clean_bullets
    from core.case_knowledge import append_facts_text, facts_in
    from core.investigation_tasks import edit_case_markdown, parse_case_requests

    case_dir = _case_dir(cases_root, case_id)
    if not case_dir.is_dir():
        raise CaseAdminError(f"no such case: {case_id!r}")
    if (case_dir / "CASE.md").is_file() or (case_dir / "CLAUDE.md").is_file():
        start_of = lambda text: text
    else:
        template = _CASE_TEMPLATE / "CASE.md"
        blank = (template.read_text(encoding="utf-8").replace("<CASE_ID>", case_id)
                 if template.is_file()
                 else f"# Case: {case_id}\n\n**Case ID:** {case_id}\n")
        start_of = lambda _text: blank

    def _append(text: str) -> str:
        start = start_of(text)
        out = append_facts_text(append_requests(start, clean_bullets(list(requests))),
                                list(facts))
        return out if out != start else text

    # Read, append and replace as one step under the brief lock: a Brief
    # save or a rerun landing in between is kept, never overwritten.
    text, out = edit_case_markdown(case_dir, _append)
    if out == text:
        return {"success": True, "requests_added": 0, "facts_added": 0}
    _sync_tasks(case_dir)
    start = start_of(text)
    return {
        "success": True,
        "requests_added": len(parse_case_requests(out)) - len(parse_case_requests(start)),
        "facts_added": len(facts_in(out)) - len(facts_in(start)),
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
    _refuse_if_busy(cases_root, case_id)
    _refuse_other_filesystem(src, cases_root)
    _refuse_if_mounted(src)
    _close_chat(case_id)

    with _while_idle(cases_root, case_id):
        if dest.exists():
            raise CaseAdminError(f"a case named {new_case_id!r} already exists")
        _rename(src, dest)
    from core.investigation_tasks import edit_case_markdown
    # The rename carries the brief's Case ID line along when it named the
    # folder; the task store then follows the brief, as a run would.
    edit_case_markdown(dest, lambda text: re.sub(
        r"(\*\*Case ID:?\*\*[:\s|]+)" + re.escape(case_id) + r"\b",
        lambda m: m.group(1) + new_case_id, text))
    _sync_tasks(dest)
    return {"success": True, "case_id": new_case_id, "previous_id": case_id}
