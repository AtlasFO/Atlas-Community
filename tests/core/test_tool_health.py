"""The board that makes a missing tool visible instead of silent."""
from __future__ import annotations

import json
from unittest.mock import patch

from core import tool_health


def test_a_missing_program_is_reported_with_what_should_install_it():
    with patch.dict(tool_health.__dict__):
        with patch("core.paths.tool_program", return_value=None):
            entries = {e["needs"]: e for e in tool_health.probe()["entries"]
                       if e["kind"] == "program"}
    assert entries, "every declared program belongs on the board"
    rip = entries["rip.pl"]
    assert rip["status"] == "missing"
    assert rip["installed_by"] == "install.sh (RegRipper)", \
        "an operator has to be told where it comes from"


def test_the_exporters_name_the_package_that_installs_them():
    """A missing esedbexport or evtexport tells the operator which apt
    package to install, on Ubuntu and with the GIFT PPA."""
    with patch("core.paths.tool_program", return_value=None):
        board = {e["needs"]: e for e in tool_health.probe()["entries"]}
    assert board["esedbexport"]["status"] == "missing"
    assert "libesedb" in board["esedbexport"]["installed_by"]
    assert "libevt" in board["evtexport"]["installed_by"]


def test_a_fallback_program_counts_as_available_not_missing():
    """bin.r2_summary prefers rizin and falls back to radare2."""
    def only_r2(name, *rest):
        return "/usr/bin/r2" if name == "r2" else None

    with patch("core.paths.tool_program", side_effect=only_r2):
        board = {e["needs"]: e for e in tool_health.probe()["entries"]}
    entry = board["rz-bin or r2"]
    assert entry["status"] == "alternative"
    assert "r2" in entry["detail"]


def test_the_install_report_round_trips(tmp_path):
    target = tmp_path / "install_report.json"
    with patch("core.paths.tool_program",
               side_effect=lambda n, *a: "/usr/bin/x" if n == "strings" else None):
        tool_health.write_install_report(target)
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["programs"]["strings"]["resolved"] == "/usr/bin/x"
    assert data["installed"] >= 1 and data["total"] > data["installed"]
    assert data["programs"]["rip.pl"]["note"], "a missing program says why"


def test_problems_lists_only_what_an_operator_can_act_on():
    with patch("core.paths.tool_program", return_value=None):
        problems = tool_health.problems()
    assert problems
    assert all(p["status"] in ("missing", "retired") for p in problems)


def test_the_dashboard_endpoint_is_wired():
    """Config → Tool health reads this route; a rename must fail here, not in
    the UI. Asserted against the route table rather than the source text, so
    moving the handler between modules does not read as a break."""
    import pathlib

    from dashboard.app import GET_ROUTES
    assert callable(GET_ROUTES.get("config/tools"))

    page = pathlib.Path("dashboard/config.html").read_text(encoding="utf-8")
    assert 'data-tab="tools"' in page and 'id="panel-tools"' in page
    assert "config/tools" in page


def test_a_pip_installed_python_program_is_found_and_runnable(tmp_path, monkeypatch):
    """pyhindsight installs hindsight.py mode 0644 into the venv's bin.

    Requiring the execute bit reported an installed program as missing;
    exec'ing it directly would fail with Permission denied. Both are wrong.
    """
    import core.paths as paths

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    script = fake_bin / "hindsight.py"
    script.write_text("print('hi')\n", encoding="utf-8")
    script.chmod(0o644)

    monkeypatch.setattr(paths, "_tool_dirs", lambda: (str(fake_bin),))
    monkeypatch.setattr("shutil.which", lambda _n: None)

    resolved = paths.tool_program("hindsight.py")
    assert resolved == str(script), "an installed program must not read as missing"
    argv = paths.program_argv(resolved)
    assert len(argv) == 2 and argv[0].endswith("python") or "python" in argv[0]
    assert argv[1] == str(script)

    # An executable program is run directly, without an interpreter prefix.
    binary = fake_bin / "chainsaw"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)
    assert paths.program_argv(str(binary)) == [str(binary)]


def test_an_executable_python_module_without_an_interpreter_line_still_runs(tmp_path):
    """A package module copied as a file keeps mode 0755 but has no #! line:
    exec'ing it fails with "Exec format error". It runs through the
    interpreter instead, while a script with a #! line is exec'd directly."""
    import subprocess
    import sys

    import core.paths as paths

    module = tmp_path / "INDXParse.py"
    module.write_text("#    This file is part of a package.\nprint('ran')\n", encoding="utf-8")
    module.chmod(0o755)
    argv = paths.program_argv(str(module))
    assert argv == [sys.executable, str(module)]
    assert subprocess.run(argv, capture_output=True, text=True).stdout == "ran\n"

    script = tmp_path / "pdfid.py"
    script.write_text("#!/usr/bin/env python3\nprint('ran')\n", encoding="utf-8")
    script.chmod(0o755)
    assert paths.program_argv(str(script)) == [str(script)]


def test_only_a_python_file_is_routed_through_the_interpreter(tmp_path):
    """A compiled program has no #! line either; it is exec'd as it is."""
    import core.paths as paths

    binary = tmp_path / "bulk_extractor"
    binary.write_bytes(b"\x7fELF\x02\x01\x01\x00")
    binary.chmod(0o755)
    assert paths.program_argv(str(binary)) == [str(binary)]


def test_an_unreadable_python_file_is_exec_d_and_left_to_the_executor(tmp_path):
    """No worse than before: when the first bytes cannot be read, the program
    runs as it is and the executor reports what happens."""
    import os

    import pytest

    import core.paths as paths

    if os.geteuid() == 0:
        pytest.skip("root reads every file")
    script = tmp_path / "INDXParse.py"
    script.write_text("# a package module\n", encoding="utf-8")
    script.chmod(0o111)
    try:
        assert paths.program_argv(str(script)) == [str(script)]
    finally:
        script.chmod(0o755)


def test_an_unreadable_directory_under_cases_does_not_break_the_scan(tmp_path, monkeypatch):
    """Every ext4 cases volume has a root-owned lost+found.

    Nine tests and the dashboard's brain review died on it with
    PermissionError: a ground-truth scan is best-effort by contract.
    """
    import core.brain.answer_key as ak

    cases = tmp_path / "cases"
    (cases / "CASE-01").mkdir(parents=True)
    blocked = cases / "lost+found"
    blocked.mkdir()
    blocked.chmod(0o000)
    monkeypatch.setattr(ak, "_cases_root", lambda: cases)
    try:
        assert ak.secrets_for_case_id("CASE-01") == []
        assert ak._find_ground_truth(blocked) is None
    finally:
        blocked.chmod(0o755)


def test_an_optional_program_is_not_reported_as_a_fault():
    """"missing" should mean "the operator can fix this". Detect It Easy has
    no Debian package and zeek sits behind an install flag: counting them as
    faults made a healthy install report four problems it did not have."""
    from unittest.mock import patch

    with patch("core.paths.tool_program", return_value=None):
        board = {e["needs"]: e for e in tool_health.probe()["entries"]}
        actionable = {p["needs"] for p in tool_health.problems()}

    assert board["die or diec"]["status"] == "optional"
    assert board["zeek"]["status"] == "optional"
    assert "--with-network-tools" in board["zeek"]["detail"]
    assert "die or diec" not in actionable and "zeek" not in actionable
    # A program that should be there is still a fault.
    assert board["rip.pl"]["status"] == "missing"
    assert "rip.pl" in actionable


def test_an_optional_program_says_how_to_install_it():
    """"Optional" must not mean "you are on your own": the board is where an
    operator finds out what to run."""
    from unittest.mock import patch

    with patch("core.paths.tool_program", return_value=None):
        entry = {e["needs"]: e for e in tool_health.probe()["entries"]}["die or diec"]

    assert entry["status"] == "optional"
    assert "install.sh" in entry["detail"], "name the command that installs it"
    assert "DIE-engine/releases" in entry["detail"], "and the manual route"
    assert "pe_scanner" in entry["detail"], "and what covers the gap meanwhile"
    assert tool_health.SOURCES["die"].startswith("install.sh"), \
        "there is an installer step for it now"


def test_a_program_installed_under_opt_is_found_and_runnable(tmp_path, monkeypatch):
    """zeek installs to /opt/zeek/bin and puts nothing on PATH.

    The board called it missing on a machine that had it, and
    net.zeek_analyze — which runs the bare name — would have failed the same
    way. Resolution and execution have to agree about where programs live.
    """
    import glob
    import os

    import core.paths as paths

    opt = tmp_path / "opt" / "zeek" / "bin"
    opt.mkdir(parents=True)
    program = opt / "zeek"
    program.write_text("#!/bin/sh\n", encoding="utf-8")
    program.chmod(0o755)

    monkeypatch.setattr(glob, "glob", lambda pat: [str(opt)] if pat == "/opt/*/bin" else [])
    monkeypatch.setattr("shutil.which", lambda _n: None)
    assert paths.tool_program("zeek") == str(program)

    # And the same directory reaches PATH, so a bare-name call can run it.
    monkeypatch.setenv("PATH", "/usr/bin")
    paths.ensure_venv_on_path()
    assert str(opt) in os.environ["PATH"].split(os.pathsep)
