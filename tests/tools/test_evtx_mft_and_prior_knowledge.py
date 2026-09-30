"""The EVTX and $MFT tools, and the prior-knowledge CASE.md section that
takes the operator's threat context.

EVTX is read through the pure-Python Evtx library (core.evtx_reader), $MFT
through the analyzeMFT CLI, and prior knowledge is plain CASE.md prose.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SYNTHETIC_MFT = FIXTURES / "synthetic_mft.bin"


@pytest.fixture()
def case(tmp_path):
    """A configured case so tools can log to a trace."""
    from core.execution_log import log
    for sub in ("analysis", "exports", "evidence"):
        (tmp_path / sub).mkdir()
    log.configure("EVTX-MFT", str(tmp_path / "analysis" / "trace.json"),
                  save_session=False)
    return tmp_path


class TestEvtxTools:
    def test_missing_file_refused(self, case):
        from tools.misc import evtx_filter
        r = evtx_filter(str(case / "evidence" / "nope.evtx"), "4624")
        assert r["success"] is False

    def test_bad_event_ids_refused(self, case):
        from tools.misc import evtx_filter
        (case / "evidence" / "x.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 40)
        r = evtx_filter(str(case / "evidence" / "x.evtx"), "not-an-id")
        assert r["success"] is False and r["gate"] == "bad_args"

    def test_parse_event_ids_shapes(self):
        from tools.misc import parse_event_ids
        assert parse_event_ids("4624,4625")[0] == {4624, 4625}
        assert parse_event_ids("(4624, 4625)")[0] == {4624, 4625}
        assert parse_event_ids([4624, "4625"])[0] == {4624, 4625}
        assert parse_event_ids("")[0] == set()

    def test_missing_library_degrades(self, case, monkeypatch):
        import core.evtx_reader as er
        monkeypatch.setattr(er, "available", lambda: False)
        (case / "evidence" / "x.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 40)
        from tools.misc import evtx_dump
        r = evtx_dump(str(case / "evidence" / "x.evtx"))
        assert r["success"] is False and r.get("gate") == "program_missing"

    def test_real_parse_when_local_sample_present(self, case):
        # No EVTX fixture is committed (a real one carries host names); this
        # runs only where a local sample.evtx is dropped in beside the tests.
        import core.evtx_reader as er
        sample = FIXTURES / "sample.evtx"
        if not er.available() or not sample.is_file():
            pytest.skip("python-evtx or local EVTX sample absent")
        from tools.misc import evtx_dump
        r = evtx_dump(str(sample), max_records=3)
        assert r["success"] and r["records"] and "<Event" in r["records"][0]


class TestMftTools:
    def test_analyzemft_parse_produces_csv(self, case):
        if not SYNTHETIC_MFT.is_file():
            pytest.skip("fixture missing")
        from core.paths import tool_program
        if not tool_program("analyzemft"):
            pytest.skip("analyzemft not installed")
        from tools.misc import analyzemft_parse
        mft = case / "evidence" / "mft.bin"
        shutil.copy(SYNTHETIC_MFT, mft)
        out = str(case / "analysis" / "mft.csv")
        r = analyzemft_parse(str(mft), out)
        assert r["success"] and Path(out).is_file()
        assert Path(out).read_text().splitlines()[0].startswith("Record Number")

    def test_analyzemft_missing_program(self, case, monkeypatch):
        # misc.py binds tool_program into its own namespace at import time.
        monkeypatch.setattr("tools.misc.tool_program", lambda n, *a: None)
        from tools.misc import analyzemft_parse
        (case / "evidence" / "m.bin").write_bytes(b"FILE" + b"\x00" * 40)
        r = analyzemft_parse(str(case / "evidence" / "m.bin"),
                             str(case / "analysis" / "m.csv"))
        assert r["success"] is False and r.get("gate") == "program_missing"

    def _mft_rules(self, tmp_path):
        rules = tmp_path / "mft_rules"
        rules.mkdir()
        (rules / "example_mft.yml").write_text("kind: mft\n")
        return rules

    @staticmethod
    def _chainsaw(monkeypatch, rows=(), stderr="", success=True, exit_code=0):
        """Fake chainsaw: records the argv and writes rows shaped like its
        JSONL for matches of kind: mft rules."""
        import json
        import tools.misc as m
        monkeypatch.setattr(m, "_bin_or_warn", lambda n: "/usr/bin/chainsaw")
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = cmd
            if success:
                Path(cmd[cmd.index("--output") + 1]).write_text(
                    "".join(json.dumps(row) + "\n" for row in rows))
            return {"success": success, "exit_code": exit_code, "stdout": "",
                    "stderr": stderr}

        monkeypatch.setattr(m, "run", fake_run)
        return seen

    def test_mft_rule_hunt_refuses_without_rules(self, case, monkeypatch):
        import tools.misc as m
        self._chainsaw(monkeypatch)
        monkeypatch.setattr(m, "_CHAINSAW_ROOTS", (str(case / "no-root"),))
        (case / "evidence" / "m.bin").write_bytes(b"FILE" + b"\x00" * 40)
        r = m.mft_rule_hunt(str(case / "evidence" / "m.bin"), str(case / "analysis"))
        assert r["success"] is False and r["gate"] == "rules_missing"
        assert "install.sh" in r["error"]

    def test_explicit_rules_must_hold_rules(self, case, monkeypatch, tmp_path):
        import tools.misc as m
        self._chainsaw(monkeypatch)
        (case / "evidence" / "m.bin").write_bytes(b"FILE" + b"\x00" * 40)
        empty = tmp_path / "empty_rules"
        empty.mkdir()
        r = m.mft_rule_hunt(str(case / "evidence" / "m.bin"), str(case / "analysis"),
                            rules_dir=str(empty))
        assert r["gate"] == "rules_missing" and str(empty) in r["error"]
        one_rule = self._mft_rules(tmp_path) / "example_mft.yml"
        r = m.mft_rule_hunt(str(case / "evidence" / "m.bin"), str(case / "analysis"),
                            rules_dir=str(one_rule))
        assert r["success"] and r["rules"] == str(one_rule)

    def test_mft_rule_hunt_refuses_a_file_that_is_no_mft(self, case, monkeypatch, tmp_path):
        import tools.misc as m
        self._chainsaw(monkeypatch)
        (case / "evidence" / "notes.txt").write_bytes(b"plain text")
        r = m.mft_rule_hunt(str(case / "evidence" / "notes.txt"), str(case / "analysis"),
                            rules_dir=str(self._mft_rules(tmp_path)))
        assert r["success"] is False and "not an $MFT" in r["error"]

    def test_an_unreadable_mft_is_an_error_not_an_exception(self, case, monkeypatch, tmp_path):
        import os
        import tools.misc as m
        if os.geteuid() == 0:
            pytest.skip("root reads every file")
        self._chainsaw(monkeypatch)
        mft = case / "evidence" / "m.bin"
        mft.write_bytes(b"FILE" + b"\x00" * 40)
        mft.chmod(0)
        try:
            r = m.mft_rule_hunt(str(mft), str(case / "analysis"),
                                rules_dir=str(self._mft_rules(tmp_path)))
        finally:
            mft.chmod(0o600)
        assert r["success"] is False and "cannot read" in r["error"]

    def test_mft_rule_hunt_command_and_summary(self, case, monkeypatch, tmp_path):
        import tools.misc as m
        rows = [
            {"name": "Example Tool", "level": "medium",
             "timestamp": "2031-02-04T12:00:00+00:00",
             "document": {"kind": "mft", "data": {
                 "FullPath": "Users/Public/toolx.exe", "IsDeleted": False}}},
            {"name": "Example Tool", "level": "medium",
             "timestamp": "2031-02-03T12:00:00+00:00",
             "document": {"kind": "mft", "data": {
                 "FullPath": "Temp/toolx.exe", "IsDeleted": True}}},
            {"name": "Credential Store Copy", "level": "critical",
             "timestamp": "2031-02-05T12:00:00+00:00",
             "document": {"kind": "mft", "data": {
                 "FullPath": "Temp/store.dit", "IsDeleted": False}}},
        ]
        stderr = ("\x1b[0m[+] Loading detection rules from: /rules\n"
                  "[!] failed to parse document '/case/evidence/host1.raw' - Bad signature\n"
                  "[!] failed to parse document '/case/evidence/host1.raw' - Bad signature\n"
                  "[+] 3 Detections found on 3 documents\n")
        seen = self._chainsaw(monkeypatch, rows=rows, stderr=stderr)
        mft = case / "evidence" / "host1.raw"
        mft.write_bytes(b"FILE" + b"\x00" * 1020)
        rules = self._mft_rules(tmp_path)
        r = m.mft_rule_hunt(str(mft), str(case / "analysis"), rules_dir=str(rules))
        cmd = seen["cmd"]
        # The banner is off, the log is not; any file name loads; one damaged
        # record does not end the hunt.
        output = cmd[cmd.index("--output") + 1]
        assert cmd == ["/usr/bin/chainsaw", "--no-banner", "hunt", str(mft), "-r", str(rules),
                       "--load-unknown", "--skip-errors", "--jsonl", "--output", output]
        assert Path(output).name.startswith("mft_rule_hunt_host1_")
        assert r["total_matches"] == 3 and r["skipped_records"] == 2
        first, second = r["by_rule"]
        assert first["rule"] == "Credential Store Copy"   # severity ranks before count
        assert second["count"] == 2 and second["deleted"] == 1
        assert second["paths"] == ["Users/Public/toolx.exe", "Temp/toolx.exe"]
        assert (second["first_seen"], second["last_seen"]) == (
            "2031-02-03T12:00:00+00:00", "2031-02-04T12:00:00+00:00")

    def test_a_failed_hunt_says_what_chainsaw_said(self, case, monkeypatch, tmp_path):
        import tools.misc as m
        self._chainsaw(monkeypatch, success=False, exit_code=1, stderr=(
            "[+] Loading detection rules from: /rules\n"
            "[x] No valid detection rules were found in the provided paths\n"))
        mft = case / "evidence" / "host1.raw"
        mft.write_bytes(b"FILE" + b"\x00" * 1020)
        r = m.mft_rule_hunt(str(mft), str(case / "analysis"),
                            rules_dir=str(self._mft_rules(tmp_path)))
        assert r["success"] is False
        assert r["error"] == "chainsaw: [x] No valid detection rules were found in the provided paths"

    def test_a_crash_without_an_error_line_reports_the_log_tail(self, case, monkeypatch, tmp_path):
        import tools.misc as m
        self._chainsaw(monkeypatch, success=False, exit_code=101, stderr=(
            "[+] Loading forensic artefacts from: /case/evidence/host1.raw\n"
            "thread 'main' panicked at 'attempt to divide by zero'\n"))
        mft = case / "evidence" / "host1.raw"
        mft.write_bytes(b"FILE" + b"\x00" * 1020)
        r = m.mft_rule_hunt(str(mft), str(case / "analysis"),
                            rules_dir=str(self._mft_rules(tmp_path)))
        assert r["success"] is False and "panicked" in r["error"]

    def test_sigma_lookup_ignores_chainsaw_format_rules(self, tmp_path, monkeypatch):
        # chainsaw's own rules/ folder handed to -s loads nothing and reports
        # no detections, so only a sigma/ folder counts.
        import tools.misc as m
        root = tmp_path / "chainsaw"
        (root / "rules" / "evtx").mkdir(parents=True)
        (root / "rules" / "evtx" / "x.yml").write_text("kind: evtx\n")
        monkeypatch.setattr(m, "_CHAINSAW_ROOTS", (str(root),))
        assert m._chainsaw_rules_dir() is None
        (root / "sigma").mkdir()
        (root / "sigma" / "s.yml").write_text("title: x\n")
        assert m._chainsaw_rules_dir() == str(root / "sigma")


class TestPriorKnowledge:
    def _case(self, tmp_path, body):
        (tmp_path / "evidence").mkdir()
        (tmp_path / "CASE.md").write_text(body)
        return tmp_path

    def test_indicators_seeded_and_theory_read(self, tmp_path):
        from core.case_knowledge import read
        c = self._case(tmp_path,
            "# Case: X\n## Investigation Requests\n- Find it.\n"
            "## What you already know\n- Ransomware; saw 203.0.113.7 in the firewall.\n")
        info = read(c)
        assert info["present"] and info["seeded"]
        assert "ip:203.0.113.7" in info["indicators"]

    def test_prior_knowledge_not_a_request(self, tmp_path):
        from core.investigation_tasks import parse_case_requests
        c = self._case(tmp_path,
            "# Case: X\n## Investigation Requests\n- Find it.\n"
            "## What you already know\n- Suspected ransomware.\n")
        assert parse_case_requests((c / "CASE.md").read_text()) == ["Find it."]

    def test_graded_case_not_seeded(self, tmp_path):
        from core.case_knowledge import read
        c = self._case(tmp_path,
            "# Case: X\n## What you already know\n- saw 203.0.113.7.\n")
        (c / "ground_truth.json").write_text('{"expected_findings": []}')
        info = read(c)
        assert info["present"] and not info["seeded"]
        assert "answer key" in info["reason"]

    def test_absent_section_is_silent(self, tmp_path):
        from core.case_knowledge import read, prompt_note
        c = self._case(tmp_path, "# Case: X\n## Investigation Requests\n- Find it.\n")
        assert read(c)["present"] is False
        assert prompt_note(c) == ""
