"""Tests for dashboard/case_admin.py — case ID validation, create (template
copy + CASE.md placeholder substitution), move, and delete (soft + purge).

All tests operate against a real tmp_path cases_root and the repo's actual
case-template/ (read-only source, never mutated) — this is deliberately an
integration-style test of the real template rather than a synthetic fixture,
since the whole point is verifying the <CASE_ID> substitution against the
real file.
"""
from __future__ import annotations

import os

import pytest

from dashboard import case_admin


@pytest.fixture
def cases_root(tmp_path):
    root = tmp_path / "cases"
    root.mkdir()
    return str(root)


class TestValidateCaseId:
    def test_empty(self):
        assert case_admin.validate_case_id("") is not None

    def test_path_separators_rejected(self):
        assert case_admin.validate_case_id("a/b") is not None
        assert case_admin.validate_case_id("a\\b") is not None
        assert case_admin.validate_case_id("../etc") is not None

    def test_too_long(self):
        assert case_admin.validate_case_id("x" * 101) is not None
        assert case_admin.validate_case_id("x" * 100) is None

    def test_bad_charset(self):
        assert case_admin.validate_case_id("has space") is not None
        assert case_admin.validate_case_id("has$dollar") is not None

    def test_valid(self):
        assert case_admin.validate_case_id("ACME-2026-0142") is None
        assert case_admin.validate_case_id("simple_case_1") is None


class TestCreateCase:
    def test_a_template_without_the_case_folders_still_gives_a_whole_case(
            self, cases_root, tmp_path, monkeypatch):
        template = tmp_path / "template"
        template.mkdir()
        (template / "CASE.md").write_text("# <CASE_ID>\n")
        monkeypatch.setattr(case_admin, "_CASE_TEMPLATE", template)
        d = case_admin.create_case(cases_root, "TEST-CASE-2")
        for sub in ("evidence", "analysis", "exports", "reports"):
            assert (d / sub).is_dir(), sub

    def test_creates_directory_from_template(self, cases_root):
        d = case_admin.create_case(cases_root, "TEST-CASE-1")
        assert d.is_dir()
        assert (d / "CASE.md").is_file()
        assert (d / "evidence").is_dir()
        assert (d / "exports").is_dir()
        assert (d / "reports").is_dir()
        assert (d / "analysis").is_dir()

    def test_substitutes_case_id_placeholder(self, cases_root):
        d = case_admin.create_case(cases_root, "SUBSTITUTED-ID")
        text = (d / "CASE.md").read_text()
        assert "<CASE_ID>" not in text
        assert "SUBSTITUTED-ID" in text
        assert "**Case ID:** SUBSTITUTED-ID" in text

    def test_seeds_investigation_requests(self, cases_root):
        d = case_admin.create_case(
            cases_root, "WITH-REQUESTS",
            requests=["Who did it?", "  ", "When did it happen?"])
        text = (d / "CASE.md").read_text()
        assert "- Who did it?" in text
        assert "- When did it happen?" in text
        # Blank/whitespace-only requests are dropped, not rendered as bullets.
        assert "-   \n" not in text

    def test_no_requests_still_creates_case(self, cases_root):
        d = case_admin.create_case(cases_root, "NO-REQUESTS")
        assert (d / "CASE.md").is_file()

    def test_requests_with_backslashes_do_not_crash(self, cases_root):
        # Regression: re.sub()'s replacement string interprets backslash
        # escapes (\1, \g<...>, \U...), so a realistic investigation
        # request like a Windows path used to crash case creation with
        # `re.error: bad escape`. Investigators write these constantly.
        d = case_admin.create_case(
            cases_root, "WINPATH-CASE",
            requests=[r"recover files from C:\Users\admin\Desktop",
                      r"check \1 and \g<name> literally"])
        text = (d / "CASE.md").read_text()
        assert r"recover files from C:\Users\admin\Desktop" in text
        assert r"check \1 and \g<name> literally" in text

    def test_invalid_id_raises_before_touching_disk(self, cases_root):
        with pytest.raises(case_admin.CaseAdminError):
            case_admin.create_case(cases_root, "../escape")
        assert os.listdir(cases_root) == []

    def test_duplicate_refused(self, cases_root):
        case_admin.create_case(cases_root, "DUP-CASE")
        with pytest.raises(case_admin.CaseAdminError, match="already exists"):
            case_admin.create_case(cases_root, "DUP-CASE")

    def test_seeded_requests_appear_in_task_store_immediately(self, cases_root):
        # Regression: the dashboard Questions tab reads .atlas/investigation_
        # tasks.json, not CASE.md directly — without reconcile_case_md() at
        # create time, requests typed in during case creation stayed
        # invisible to the Questions tab until the first `atlas run`.
        from core.investigation_tasks import load_tasks
        d = case_admin.create_case(
            cases_root, "SEEDED-QUESTIONS",
            requests=["What happened on the Host?"])
        store = load_tasks(d)
        texts = [t["text"] for t in store["tasks"]]
        assert "What happened on the Host?" in texts


class TestMoveCase:
    def test_renames_directory(self, cases_root):
        case_admin.create_case(cases_root, "OLD-ID")
        result = case_admin.move_case(cases_root, "OLD-ID", "NEW-ID")
        assert result["success"] is True
        assert not os.path.exists(os.path.join(cases_root, "OLD-ID"))
        assert os.path.isdir(os.path.join(cases_root, "NEW-ID"))

    def test_updates_case_md_id_line(self, cases_root):
        case_admin.create_case(cases_root, "RENAME-ME")
        case_admin.move_case(cases_root, "RENAME-ME", "RENAMED")
        text = (open(os.path.join(cases_root, "RENAMED", "CASE.md")).read())
        assert "**Case ID:** RENAMED" in text
        assert "**Case ID:** RENAME-ME" not in text

    def test_refuses_nonexistent_source(self, cases_root):
        with pytest.raises(case_admin.CaseAdminError, match="no such case"):
            case_admin.move_case(cases_root, "GHOST", "WHATEVER")

    def test_refuses_when_destination_exists(self, cases_root):
        case_admin.create_case(cases_root, "SRC")
        case_admin.create_case(cases_root, "DST")
        with pytest.raises(case_admin.CaseAdminError, match="already exists"):
            case_admin.move_case(cases_root, "SRC", "DST")
        # Source must be untouched by the refused move.
        assert os.path.isdir(os.path.join(cases_root, "SRC"))


class TestDeleteCase:
    def test_soft_delete_moves_to_trash(self, cases_root):
        case_admin.create_case(cases_root, "TO-DELETE")
        result = case_admin.delete_case(cases_root, "TO-DELETE")
        assert result["action"] == "moved_to_trash"
        assert not os.path.exists(os.path.join(cases_root, "TO-DELETE"))
        assert os.path.isdir(result["location"])
        assert (os.path.join(cases_root, ".deleted")
               in result["location"])

    def test_purge_removes_entirely(self, cases_root):
        case_admin.create_case(cases_root, "TO-PURGE")
        result = case_admin.delete_case(cases_root, "TO-PURGE", purge=True)
        assert result["action"] == "purged"
        assert not os.path.exists(os.path.join(cases_root, "TO-PURGE"))
        # Nothing shows up under a trash dir for a purge.
        trash = os.path.join(cases_root, ".deleted")
        assert not os.path.isdir(trash) or os.listdir(trash) == []

    def test_refuses_nonexistent_case(self, cases_root):
        with pytest.raises(case_admin.CaseAdminError, match="no such case"):
            case_admin.delete_case(cases_root, "GHOST")

    def test_delete_then_recreate_same_id(self, cases_root):
        # The soft-delete's whole point: freeing up the ID for reuse while
        # keeping the old content recoverable in .deleted/.
        case_admin.create_case(cases_root, "REUSED-ID")
        case_admin.delete_case(cases_root, "REUSED-ID")
        d = case_admin.create_case(cases_root, "REUSED-ID")
        assert d.is_dir()


class TestAppendToBrief:
    """The start dialog's quick-add writes the same brief the Brief tab
    edits, and the task store follows at once."""

    def test_appends_questions_and_facts_and_syncs_tasks(self, cases_root):
        import json
        from pathlib import Path
        case_admin.create_case(cases_root, "CaseA", requests=["What happened?"])
        out = case_admin.append_to_brief(
            cases_root, "CaseA",
            requests=["Was data taken?", "what happened?"],
            facts=["IP 10.0.0.5 is the print server."])
        assert out == {"success": True, "requests_added": 1, "facts_added": 1}
        case = Path(cases_root) / "CaseA"
        md = (case / "CASE.md").read_text(encoding="utf-8")
        assert "- Was data taken?" in md and "- IP 10.0.0.5 is the print server." in md
        tasks = json.loads((case / ".atlas" / "investigation_tasks.json")
                           .read_text(encoding="utf-8"))
        assert "Was data taken?" in {t["text"] for t in tasks["tasks"]}
        again = case_admin.append_to_brief(cases_root, "CaseA", requests=["Was data taken?"])
        assert again == {"success": True, "requests_added": 0, "facts_added": 0}

    def test_a_case_without_a_brief_gets_the_template(self, cases_root):
        from pathlib import Path
        (Path(cases_root) / "Bare").mkdir()
        out = case_admin.append_to_brief(cases_root, "Bare", requests=["Why?"])
        assert out["requests_added"] == 1
        md = (Path(cases_root) / "Bare" / "CASE.md").read_text(encoding="utf-8")
        assert "**Case ID:** Bare" in md and "- Why?" in md

    def test_unknown_case_is_refused(self, cases_root):
        with pytest.raises(case_admin.CaseAdminError, match="no such case"):
            case_admin.append_to_brief(cases_root, "Nope", requests=["x"])


class TestCaseMd:
    def test_reads_the_created_template(self, cases_root):
        case_admin.create_case(cases_root, "MD-CASE-1")
        result = case_admin.read_case_md(cases_root, "MD-CASE-1")
        assert result["exists"] is True
        assert "MD-CASE-1" in result["content"]

    def test_read_refuses_nonexistent_case(self, cases_root):
        with pytest.raises(case_admin.CaseAdminError, match="no such case"):
            case_admin.read_case_md(cases_root, "GHOST-MD")

    def test_write_then_read_round_trips(self, cases_root):
        case_admin.create_case(cases_root, "MD-CASE-2")
        case_admin.write_case_md(cases_root, "MD-CASE-2", "# Updated brief\n")
        result = case_admin.read_case_md(cases_root, "MD-CASE-2")
        assert result["content"] == "# Updated brief\n"

    def test_write_refuses_nonexistent_case(self, cases_root):
        with pytest.raises(case_admin.CaseAdminError, match="no such case"):
            case_admin.write_case_md(cases_root, "GHOST-MD-2", "x")

    def test_write_leaves_no_tmp_file_behind(self, cases_root):
        d = case_admin.create_case(cases_root, "MD-CASE-3")
        case_admin.write_case_md(cases_root, "MD-CASE-3", "content")
        assert not (d / "CASE.md.tmp").exists()

    def test_a_code_block_that_never_closes_is_reported_on_save_and_read(self, cases_root):
        case_admin.create_case(cases_root, "MD-CASE-6")
        broken = ("**Case ID:** MD-CASE-6\n\n## Notes\n```\nraw output\n\n"
                  "## Investigation Requests\n- Was data taken from CORP-FS01?\n")
        saved = case_admin.write_case_md(cases_root, "MD-CASE-6", broken)
        assert saved["success"] and saved["unclosed_fence"]["line"] == 4
        assert saved["unclosed_fence"]["hidden_requests"] == 1
        assert case_admin.read_case_md(cases_root, "MD-CASE-6")["unclosed_fence"]["line"] == 4
        fixed = broken.replace("raw output\n", "raw output\n```\n")
        assert case_admin.write_case_md(cases_root, "MD-CASE-6", fixed)["unclosed_fence"] is None
        assert case_admin.read_case_md(cases_root, "MD-CASE-6")["unclosed_fence"] is None

    def test_missing_case_md_reports_not_exists(self, cases_root):
        d = case_admin.create_case(cases_root, "MD-CASE-4")
        (d / "CASE.md").unlink()
        result = case_admin.read_case_md(cases_root, "MD-CASE-4")
        assert result == {"exists": False, "content": ""}

    def test_edited_requests_appear_in_task_store_immediately(self, cases_root):
        # Same regression as create_case's version, for the edit-then-save
        # path in the dashboard's CASE.md editor.
        from core.investigation_tasks import load_tasks
        d = case_admin.create_case(cases_root, "MD-CASE-5")
        case_admin.write_case_md(
            cases_root, "MD-CASE-5",
            "**Case ID:** MD-CASE-5\n\n"
            "## Investigation Requests\n"
            "- Are there signs of data exfiltration?\n")
        store = load_tasks(d)
        texts = [t["text"] for t in store["tasks"]]
        assert "Are there signs of data exfiltration?" in texts
