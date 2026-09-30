"""The Settings card that refreshes the MITRE tables: it runs the builder
in the background, refuses a second run, reports version and counts on
success and the builder's own words on failure, and never claims to be
running after the process that ran it is gone."""
import io
import json
import time
from unittest.mock import patch

import pytest

from dashboard import auth, config_mitre


class FakeProc:
    def __init__(self, lines, rc=0, delay=0.0):
        self.stderr = io.StringIO("".join(l + "\n" for l in lines))
        self._rc, self._delay = rc, delay
        self._done = False

    def poll(self):
        return None if not self._done else self._rc

    def wait(self):
        time.sleep(self._delay)
        self._done = True
        return self._rc


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    monkeypatch.setattr(config_mitre, "STATE_PATH", tmp_path / "state.json")
    monkeypatch.setattr(config_mitre, "runtime_dir", lambda: runtime)
    monkeypatch.setattr(config_mitre, "_proc", None)
    return runtime


def _write_tables(directory, version="v9.9", mitigations=True):
    for name in config_mitre.TABLES:
        if name == "mitigations" and not mitigations:
            continue
        (directory / f"mitre_{name}.json").write_text(json.dumps({
            "_meta": {"version": version, "built_at": "2026-01-01T00:00:00+00:00"},
            name: {"X1": {}, "X2": {}},
        }))


def _settle():
    for _ in range(50):
        if config_mitre._load_state().get("state") != "running":
            return
        time.sleep(0.02)


class TestStatus:
    def test_reports_installed_and_bundled_versions_and_counts(self, sandbox):
        _write_tables(sandbox, mitigations=False)
        s = config_mitre.status()
        assert s["installed"]["version"] == "v9.9" and s["installed"]["techniques"] == 2
        assert s["installed"]["mitigations"] is None      # a table not yet built reads as absent
        assert s["bundled"]["present"] and s["bundled"]["version"]
        assert s["refresh"]["state"] == "idle"

    def test_nothing_installed_is_said_not_raised(self, sandbox):
        assert not config_mitre.status()["installed"]["present"]

    def test_a_refresh_that_died_with_the_dashboard_is_not_running_forever(self, sandbox):
        config_mitre._save_state({"state": "running", "message": "", "log": []})
        s = config_mitre.status()["refresh"]
        assert s["state"] == "error" and "interrupted" in s["message"]


class TestRefresh:
    def test_success_records_version_and_counts(self, sandbox):
        def fake_popen(*a, **k):
            _write_tables(sandbox, version="v19.9")
            return FakeProc(["[build_mitre_cache] ATT&CK release: v19.9",
                             "[build_mitre_cache] wrote 2 techniques"])
        with patch.object(config_mitre.subprocess, "Popen", side_effect=fake_popen):
            out = config_mitre.start_refresh()
        assert out["success"] and out["refresh"]["state"] == "running"
        _settle()
        st = config_mitre.status()["refresh"]
        assert st["state"] == "success" and st["version"] == "v19.9"
        assert "2 techniques" in st["message"] and "2 mitigations" in st["message"]
        assert any("release" in l for l in st["log"])

    def test_the_builder_is_pointed_at_this_machines_tables(self, sandbox):
        seen = {}
        def fake_popen(argv, **k):
            seen["argv"] = argv
            return FakeProc([])
        with patch.object(config_mitre.subprocess, "Popen", side_effect=fake_popen):
            config_mitre.start_refresh()
        _settle()
        assert "tools.mitre.build_mitre_cache" in seen["argv"]
        assert seen["argv"][-1] == str(sandbox)

    def test_failure_reports_the_builders_last_line(self, sandbox):
        with patch.object(config_mitre.subprocess, "Popen",
                          return_value=FakeProc(["urllib.error.URLError: no route"], rc=1)):
            config_mitre.start_refresh()
        _settle()
        st = config_mitre.status()["refresh"]
        assert st["state"] == "error" and "no route" in st["message"]

    def test_a_second_refresh_is_refused_while_one_runs(self, sandbox):
        with patch.object(config_mitre.subprocess, "Popen",
                          return_value=FakeProc([], delay=0.3)):
            first = config_mitre.start_refresh()
            second = config_mitre.start_refresh()
        assert first["success"] and not second["success"]
        assert "already running" in second["error"]
        _settle()

    def test_a_builder_that_cannot_start_is_an_error_not_a_crash(self, sandbox):
        with patch.object(config_mitre.subprocess, "Popen", side_effect=OSError("no python")):
            out = config_mitre.start_refresh()
        assert not out["success"] and "no python" in out["error"]
        assert config_mitre.status()["refresh"]["state"] == "error"


class TestWiring:
    def test_routes_are_admin_only(self):
        assert auth.effective_min_role("config/mitre") == "admin"
        assert auth.effective_min_role("config/mitre/refresh") == "admin"

    def test_the_refresh_is_in_its_own_settings_section(self):
        from pathlib import Path
        page = Path("dashboard/config.html").read_text(encoding="utf-8")
        mitre_panel = page[page.index('id="panel-mitre"'):page.index('id="panel-tools"')]
        assert 'id="mitre-refresh-btn"' in mitre_panel and 'id="mitre-state"' in mitre_panel
        assert 'data-tab="mitre"' in page
