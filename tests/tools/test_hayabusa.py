"""tools/hayabusa.py: finding the release, the Hayabusa 4 command line, the
summary built from its JSONL, and the triage, status and job tools. The
executable is faked, so these tests run where Hayabusa is not installed."""
import json
from pathlib import Path

import pytest

import tools.hayabusa as hb
from core.paths import unique_output_stem


def _exe(path: Path, script: str = "#!/bin/sh\nexit 0\n") -> Path:
    path.write_text(script)
    path.chmod(0o755)
    return path


@pytest.fixture
def fake_home(monkeypatch, tmp_path):
    """A release unpacked the way install.sh leaves it: the executable beside
    a rules/ folder, on an x86_64 machine."""
    home = tmp_path / "hayabusa_home"
    rules = home / "rules"
    rules.mkdir(parents=True)
    for i in range(150):  # above the broken-unpack threshold
        (rules / f"rule{i}.yml").write_text("title: x")
    _exe(home / "hayabusa-4.0.0-lin-x64-musl")
    monkeypatch.setattr(hb, "_home", lambda: home)
    monkeypatch.setattr(hb.platform, "machine", lambda: "x86_64")
    return home


def _jsonl(path: Path, rows) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return path


class TestLocate:
    def test_newest_build_for_this_cpu_wins(self, fake_home):
        _exe(fake_home / "hayabusa-3.8.0-lin-x64-musl")
        _exe(fake_home / "hayabusa-4.0.0-lin-x64-gnu")
        _exe(fake_home / "hayabusa-4.0.0-lin-aarch64-musl")
        _exe(fake_home / "hayabusa-4.0.0-mac-x64")
        assert hb._binary().name == "hayabusa-4.0.0-lin-x64-musl"

    def test_glibc_build_when_there_is_no_musl_build(self, fake_home):
        (fake_home / "hayabusa-4.0.0-lin-x64-musl").unlink()
        _exe(fake_home / "hayabusa-3.8.0-lin-x64-musl")
        _exe(fake_home / "hayabusa-4.0.0-lin-x64-gnu")
        assert hb._binary().name == "hayabusa-4.0.0-lin-x64-gnu"

    def test_a_build_for_another_cpu_is_not_used(self, fake_home, monkeypatch):
        monkeypatch.setattr(hb.platform, "machine", lambda: "aarch64")
        monkeypatch.setattr(hb, "_which", lambda name: None)
        assert hb._binary() is None

    def test_non_executable_file_ignored(self, fake_home, monkeypatch):
        (fake_home / "hayabusa-4.0.0-lin-x64-musl").chmod(0o644)
        monkeypatch.setattr(hb, "_which", lambda name: None)
        assert hb._binary() is None

    def test_home_from_environment(self, monkeypatch, tmp_path):
        monkeypatch.setenv("ATLAS_HAYABUSA_HOME", str(tmp_path))
        assert hb._home() == tmp_path
        monkeypatch.setenv("ATLAS_HAYABUSA_HOME", str(tmp_path / "missing"))
        assert hb._home() is None


class TestCmd:
    def test_file_vs_directory(self, fake_home, tmp_path):
        evtx = tmp_path / "Security.evtx"
        evtx.write_bytes(b"ElfFile")
        cmd = hb._cmd(str(evtx), "/out/h.jsonl")
        assert cmd[cmd.index("--file") + 1] == str(evtx)
        cmd = hb._cmd(str(tmp_path), "/out/h.jsonl")
        assert cmd[cmd.index("--directory") + 1] == str(tmp_path)

    def test_hayabusa_4_command_line(self, fake_home):
        # Hayabusa 4 replaced json-timeline with dfir-timeline and -L with
        # --output-type; the old command exits "unrecognized subcommand".
        cmd = hb._cmd("/x", "/out/h.jsonl", "high", "super-verbose")
        assert cmd[1] == "dfir-timeline" and "json-timeline" not in cmd
        assert cmd[cmd.index("--output-type") + 1] == "jsonl"
        assert cmd[cmd.index("--output") + 1] == "/out/h.jsonl"
        assert cmd[cmd.index("--profile") + 1] == "super-verbose"
        assert cmd[cmd.index("--min-level") + 1] == "high"
        assert cmd[cmd.index("--rules") + 1] == str(fake_home / "rules")
        for flag in ("--iso-8601", "--no-wizard", "--clobber", "--quiet"):
            assert flag in cmd

    def test_short_level_names_expanded(self, fake_home):
        cmd = hb._cmd("/x", "/out/h.jsonl", "crit")
        assert cmd[cmd.index("--min-level") + 1] == "critical"

    def test_raises_when_unavailable(self, monkeypatch):
        monkeypatch.setattr(hb, "_binary", lambda: None)
        monkeypatch.setattr(hb, "_rules", lambda: None)
        with pytest.raises(RuntimeError):
            hb._cmd("/x", "/out/h.jsonl")


class TestLevels:
    def test_only_real_levels_are_accepted(self):
        for ok in ("informational", "info", "LOW", "med", "medium", "high", "crit", "critical"):
            assert hb._level_error(ok) is None, ok
        for bad in ("medicine", "highway", "h", "i", "severe", ""):
            assert hb._level_error(bad) is not None, bad


class TestStatus:
    def test_healthy_install(self, fake_home):
        s = hb.status()
        assert s["installed"] and s["healthy"] and s["rule_count"] == 150

    def test_a_build_without_the_scan_command_is_unhealthy(self, fake_home):
        _exe(fake_home / "hayabusa-4.0.0-lin-x64-musl", "#!/bin/sh\nexit 2\n")
        s = hb.status()
        assert s["healthy"] is False
        assert any("dfir-timeline" in p for p in s["problems"])

    def test_a_configured_home_that_is_missing_is_named(self, monkeypatch, tmp_path):
        monkeypatch.setenv("ATLAS_HAYABUSA_HOME", str(tmp_path / "missing"))
        monkeypatch.setattr(hb, "_which", lambda name: None)
        s = hb.status()
        assert s["installed"] is False
        assert "ATLAS_HAYABUSA_HOME" in s["problems"][0]


class TestUnavailable:
    @pytest.fixture(autouse=True)
    def no_hayabusa(self, monkeypatch):
        monkeypatch.setattr(hb, "_home", lambda: None)
        monkeypatch.setattr(hb, "_which", lambda name: None)

    def test_status_reports_not_installed(self):
        r = hb.status()
        assert r["success"] and r["installed"] is False
        assert "ATLAS_HAYABUSA_HOME" in r["error"]

    def test_triage_says_how_to_install(self, tmp_path):
        r = hb.triage("/x", str(tmp_path / "out"))
        assert r["success"] is False and "ATLAS_HAYABUSA_HOME" in r["error"]


class TestTriage:
    @staticmethod
    def _run_writing(rows, stdout="", stderr="", success=True):
        def fake_run(cmd, **kw):
            if rows is not None:
                _jsonl(Path(cmd[cmd.index("--output") + 1]), rows)
            out = kw["stdout_filter"](stdout) if kw.get("stdout_filter") else stdout
            return {"success": success, "exit_code": 0 if success else 1,
                    "stdout": out, "stderr": stderr}
        return fake_run

    def test_success_summarises_and_names_files_not_scanned(self, fake_home, tmp_path, monkeypatch):
        logs = tmp_path / "evidence" / "Logs"
        logs.mkdir(parents=True)
        rows = [{"Timestamp": "2031-02-04T12:00:00Z", "RuleTitle": "Example Rule",
                 "Level": "high", "Computer": "WS01", "MitreTags": ["T1021.002"]}]
        console = ("\x1b[0mTotal event log files: 3\n"
                   "Evtx files loaded after channel filter: 2\n")
        monkeypatch.setattr(hb, "run", self._run_writing(rows, stdout=console))
        r = hb.triage(str(logs), str(tmp_path / "analysis" / "hayabusa"))
        assert r["success"] and r["detections"] == 1
        assert r["techniques"] == {"T1021.002": 1} and r["hosts"] == {"WS01": 1}
        assert r["evtx_files"] == {"found": 3, "scanned": 2}
        assert r["warning"].startswith("1 of 3 .evtx files were not scanned")
        assert r["output_path"].endswith(".jsonl") and "\x1b" not in r["stdout"]
        assert "mitre_techniques=" in r["hint"]

    def test_no_warning_when_every_file_was_scanned(self, fake_home, tmp_path, monkeypatch):
        console = "Total event log files: 2\nEvtx files loaded after channel filter: 2\n"
        monkeypatch.setattr(hb, "run", self._run_writing([], stdout=console))
        r = hb.triage(str(tmp_path), str(tmp_path / "analysis" / "hayabusa"))
        assert r["success"] and r["detections"] == 0 and "warning" not in r

    def test_error_line_surfaces_on_failure(self, fake_home, tmp_path, monkeypatch):
        # Hayabusa writes the line to stderr, behind a colour reset code.
        monkeypatch.setattr(hb, "run", self._run_writing(
            None, stdout="Start time\n", stderr="\x1b[0m[ERROR] No .evtx files were found.",
            success=False))
        r = hb.triage(str(tmp_path), str(tmp_path / "analysis"))
        assert r["error"] == "Hayabusa: [ERROR] No .evtx files were found."

    def test_error_line_with_exit_code_zero_and_no_output_is_a_failure(
            self, fake_home, tmp_path, monkeypatch):
        monkeypatch.setattr(hb, "run", self._run_writing(
            None, stderr="[ERROR] The file does not exist."))
        r = hb.triage(str(tmp_path), str(tmp_path / "analysis"))
        assert r["success"] is False and "does not exist" in r["error"]

    def test_output_to_evidence_blocked(self, fake_home):
        with pytest.raises(ValueError):
            hb.triage("/x", "/cases/foo/evidence/out")

    def test_unknown_level_refused(self, fake_home, tmp_path):
        r = hb.triage(str(tmp_path), str(tmp_path / "analysis"), min_level="severe")
        assert r["success"] is False and "informational" in r["error"]

    def test_broken_rules_folder_refused(self, fake_home, tmp_path):
        for rule in (fake_home / "rules").glob("*.yml"):
            rule.unlink()
        r = hb.triage(str(tmp_path), str(tmp_path / "analysis"))
        assert r["success"] is False and "0 rule files" in r["error"]
        assert hb.status()["healthy"] is False


class TestSummarize:
    def test_counts_and_techniques(self, tmp_path):
        rows = [
            {"Timestamp": "2031-02-04T01:00:00Z", "RuleTitle": "PsExec Svc",
             "Level": "high", "Computer": "CORP-DC01",
             "MitreTags": ["T1021.002", "T1569.002", "Exec"]},
            {"Timestamp": "2031-02-04T02:00:00Z", "RuleTitle": "PsExec Svc",
             "Level": "high", "Computer": "WS01",
             "MitreTags": "T1021.002"},          # one string instead of a list
            {"Timestamp": "2031-02-04T03:00:00Z", "RuleTitle": "Logon",
             "Level": "info", "Computer": "CORP-DC01", "MitreTags": []},
        ]
        s, detections = hb._tally(str(_jsonl(tmp_path / "h.jsonl", rows)))
        assert detections == 3 and s["detections"] == 3
        assert s["levels"] == {"high": 2, "informational": 1}
        assert s["techniques"] == {"T1021.002": 2, "T1569.002": 1}
        assert s["hosts"] == {"CORP-DC01": 2, "WS01": 1}
        assert s["span"] == {"first": "2031-02-04T01:00:00Z", "last": "2031-02-04T03:00:00Z"}
        top = s["rules"][0]
        assert top["title"] == "PsExec Svc" and top["count"] == 2
        assert top["techniques"] == ["T1021.002", "T1569.002"]
        assert top["hosts"] == ["CORP-DC01", "WS01"]
        assert (top["first"], top["last"]) == ("2031-02-04T01:00:00Z", "2031-02-04T02:00:00Z")

    def test_min_level_filter(self, tmp_path):
        rows = [{"RuleTitle": "A", "Level": "crit"}, {"RuleTitle": "B", "Level": "low"}]
        s, detections = hb._tally(str(_jsonl(tmp_path / "h.jsonl", rows)), min_level="high")
        assert detections == 2 and s["detections"] == 1
        assert s["levels"] == {"critical": 1} and s["min_level"] == "high"

    def test_severity_orders_rules(self, tmp_path):
        rows = [{"RuleTitle": "Noise", "Level": "low"}] * 5 + [
            {"RuleTitle": "Rare", "Level": "high"}]
        s, _ = hb._tally(str(_jsonl(tmp_path / "h.jsonl", rows)))
        assert [r["title"] for r in s["rules"]] == ["Rare", "Noise"]

    def test_skips_malformed_lines(self, tmp_path):
        p = tmp_path / "h.jsonl"
        p.write_text('{"RuleTitle": "A", "Level": "high"}\nnot json\n\n[1]\n')
        s, _ = hb._tally(str(p))
        assert s["detections"] == 1

    def test_summary_tool_on_missing_file(self):
        assert hb.summary("/nonexistent.jsonl")["success"] is False

    def test_summary_tool_refuses_unknown_level(self, tmp_path):
        p = tmp_path / "h.jsonl"
        p.write_text("")
        assert hb.summary(str(p), min_level="severe")["success"] is False

    def test_summary_refuses_a_file_that_is_not_hayabusa_output(self, tmp_path):
        p = _jsonl(tmp_path / "other.jsonl", [{"name": "Example Tool", "level": "high"}])
        r = hb.summary(str(p))
        assert r["success"] is False and "RuleTitle" in r["error"]


class TestOutputStem:
    def test_unique_across_hosts(self, tmp_path):
        a = tmp_path / "HOST-A" / "evidence"
        b = tmp_path / "HOST-B" / "evidence"
        a.mkdir(parents=True), b.mkdir(parents=True)
        sa, sb = unique_output_stem(str(a)), unique_output_stem(str(b))
        assert sa != sb
        assert sa.startswith("evidence_") and sb.startswith("evidence_")
        assert len(sa.rsplit("_", 1)[1]) == 8

    def test_deterministic_and_sanitized(self, tmp_path):
        p = tmp_path / "$MFT"
        assert unique_output_stem(str(p)) == unique_output_stem(str(p))
        assert "$" not in unique_output_stem(str(p))


class TestJobs:
    def test_registry_wired(self):
        import tools.jobs as jobs
        assert "hayabusa_triage" in jobs._JOB_BUILDERS
        assert jobs._JOB_BUILDERS["hayabusa_triage"][0] is hb._cmd

    def test_job_refuses_an_unknown_level(self, fake_home, tmp_path):
        import tools.jobs as jobs
        r = jobs.job_start_hayabusa(str(tmp_path), str(tmp_path / "analysis" / "hb"),
                                    min_level="severe")
        assert r["success"] is False and "informational" in r["error"]

    def test_job_says_how_to_install(self, monkeypatch, tmp_path):
        import tools.jobs as jobs
        monkeypatch.setattr(hb, "_home", lambda: None)
        monkeypatch.setattr(hb, "_which", lambda name: None)
        r = jobs.job_start_hayabusa(str(tmp_path), str(tmp_path / "analysis" / "hb"))
        assert r["success"] is False and "ATLAS_HAYABUSA_HOME" in r["error"]
