"""Every writer of a case brief goes through write_case_markdown or
edit_case_markdown, under one lock per case: a writer that read the brief
earlier says which version it started from and is refused when the brief
changed since, so a stale editor, a quick-add or a rerun's fact never erase
one another. Invented cases only."""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from core import case_knowledge
from core.investigation_tasks import (
    CaseMarkdownConflict,
    case_markdown_version,
    edit_case_markdown,
    read_case_markdown,
    write_case_markdown,
)

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "CASE-A"
    d.mkdir()
    (d / "CASE.md").write_text("**Case ID:** CASE-A\n\n## Investigation Requests\n- What ran on CORP-WS01?\n",
                               encoding="utf-8")
    return d


def test_a_stale_version_is_refused_and_the_brief_is_kept(case):
    seen = case_markdown_version(read_case_markdown(case))
    write_case_markdown(case, read_case_markdown(case) + "- Who used jane.doe?\n", base_version=seen)
    kept = read_case_markdown(case)
    with pytest.raises(CaseMarkdownConflict) as err:
        write_case_markdown(case, "# stale editor text\n", base_version=seen)
    assert read_case_markdown(case) == kept
    assert err.value.current == kept and err.value.version == case_markdown_version(kept)


def test_the_current_version_writes(case):
    v = case_markdown_version(read_case_markdown(case))
    write_case_markdown(case, "# new\n", base_version=v)
    assert read_case_markdown(case) == "# new\n"


def test_line_ends_count_as_a_reader_sees_them(case):
    write_case_markdown(case, "a\r\nb\r\n")
    assert case_markdown_version("a\r\nb\r\n") == case_markdown_version(read_case_markdown(case))


def test_a_brief_kept_as_claude_md_is_read_versioned_and_written_there(tmp_path):
    d = tmp_path / "CASE-B"
    d.mkdir()
    (d / "CLAUDE.md").write_text("**Case ID:** CASE-B\n", encoding="utf-8")
    v = case_markdown_version(read_case_markdown(d))
    with pytest.raises(CaseMarkdownConflict):
        write_case_markdown(d, "x\n", base_version=case_markdown_version(""))
    write_case_markdown(d, "**Case ID:** CASE-B\n- note\n", base_version=v)
    assert not (d / "CASE.md").exists()
    assert "- note" in (d / "CLAUDE.md").read_text(encoding="utf-8")


def test_an_edit_that_changes_nothing_writes_nothing(case):
    before = (case / "CASE.md").stat().st_mtime_ns
    time.sleep(0.01)
    assert edit_case_markdown(case, lambda t: t)[0] == read_case_markdown(case)
    assert (case / "CASE.md").stat().st_mtime_ns == before


def test_the_lock_directory_is_made_when_the_case_has_none(case):
    assert not (case / ".atlas").exists()
    write_case_markdown(case, "# x\n")
    assert (case / ".atlas" / "brief.lock").is_file()


def test_facts_from_a_rerun_go_through_the_lock_and_keep_other_lines(case):
    assert case_knowledge.append_facts(case, ["10.0.0.5 is the print server."]) == ["10.0.0.5 is the print server."]
    md = read_case_markdown(case)
    assert "- What ran on CORP-WS01?" in md and "10.0.0.5 is the print server." in md
    assert case_knowledge.remove_fact(case, "10.0.0.5 is the print server.") is True
    assert "10.0.0.5" not in read_case_markdown(case)
    assert case_knowledge.remove_fact(case, "10.0.0.5 is the print server.") is False


# Another process holding the brief lock: a plain child (no fork of this
# multi-threaded test process) that says when it holds it.
_HOLDER = """
import sys, time
from pathlib import Path
from core.investigation_tasks import _BriefLock
with _BriefLock(Path(sys.argv[1])):
    print("held", flush=True)
    time.sleep(float(sys.argv[2]))
"""


def _quick_add(case):
    from dashboard import case_admin
    case_admin.append_to_brief(str(case.parent), case.name, requests=["Was data taken?"])


@pytest.mark.parametrize("writer", [
    lambda c: edit_case_markdown(c, lambda t: t + "- appended while held\n"),
    lambda c: case_knowledge.append_facts(c, ["10.0.0.5 is the print server."]),   # rerun -q
    _quick_add,                                                                       # start dialog
], ids=["edit", "rerun_fact", "quick_add"])
def test_a_writer_waits_for_another_process_that_holds_the_brief(case, writer):
    holder = subprocess.Popen([sys.executable, "-c", _HOLDER, str(case), "0.8"],
                              stdout=subprocess.PIPE, text=True, cwd=ROOT)
    try:
        assert holder.stdout.readline().strip() == "held"
        t0 = time.monotonic()
        before = read_case_markdown(case)
        writer(case)
        waited = time.monotonic() - t0
    finally:
        holder.wait(5)
        holder.stdout.close()
    assert waited >= 0.5, waited
    assert read_case_markdown(case) != before
