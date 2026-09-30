"""Increment 2 — OS-aware detector registry.

Covers the central registry (`monitoring/detectors.py`) that replaced the four
scattered hardcoded tables in the watcher, plus the OS-awareness it gives
`baseline_capture` and `start_watcher`.
"""
import json

import pytest

from monitoring import detectors, render
from tools import monitor as monitor_mod


# ── Registry ↔ template completeness ─────────────────────────────────────────

class TestRegistryTemplateCompleteness:
    def test_every_template_has_a_registry_entry(self):
        # Every detector template shipped under artifacts/ must be described by
        # the registry, or the watcher can't dedup/summarize/severity-tag it
        # with anything but defaults.
        for name in render.list_detector_templates():
            assert name in detectors.DETECTORS, f"{name} missing from registry"

    def test_every_registered_detector_has_a_template(self):
        templates = set(render.list_detector_templates())
        for name, spec in detectors.DETECTORS.items():
            if spec.synthetic:
                continue  # behavior rules have no template
            stem = detectors.template_stem(name)
            assert stem in templates, f"{name} has no template file"

    def test_synthetic_detectors_are_not_pushable(self):
        # Behavior rules must never appear in known_detectors / platform lists,
        # or start_watcher would try to render+push a nonexistent template.
        syn = set(detectors.synthetic_detectors())
        assert syn == {"Behavior.SpawnBurst", "Behavior.ConnFanout",
                       "Behavior.FirstSeenBinary", "Behavior.RareParentChild",
                       "Behavior.DnsAnomaly", "Behavior.AuthBurst"}
        assert syn.isdisjoint(detectors.known_detectors())
        assert syn.isdisjoint(detectors.detectors_for_platform("linux"))
        assert syn.isdisjoint(detectors.detectors_for_platform("windows"))

    def test_platforms_partition_the_registry(self):
        linux = detectors.detectors_for_platform("linux")
        windows = detectors.detectors_for_platform("windows")
        # Every detector is exactly one of linux/windows, no overlap, no orphans.
        assert set(linux) | set(windows) == set(detectors.known_detectors())
        assert set(linux) & set(windows) == set()
        assert windows, "expected Windows detectors after increment 4"

    def test_windows_detectors_declare_sysmon_where_realtime(self):
        # Sysmon EID-backed detectors declare the dependency; the poll-based
        # persistence detector does not.
        assert "sysmon" in detectors.DETECTORS["Custom.Atlas.WinNewProcess"].requires
        assert "sysmon" in detectors.DETECTORS["Custom.Atlas.WinNewNetwork"].requires
        assert detectors.DETECTORS["Custom.Atlas.WinNewPersistence"].requires == ()


# ── Signature / summary / severity parity with the old watcher tables ────────

class TestSignatureParity:
    def test_new_process_signature(self):
        row = {"image_path": "/tmp/x", "pid": 42, "started_utc": "T"}
        assert detectors.row_signature("Custom.Atlas.NewProcess", row) == "/tmp/x|42|T"

    def test_new_persistence_signature(self):
        row = {"path": "/etc/cron.d/evil", "mtime_utc": "M"}
        assert detectors.row_signature("Custom.Atlas.NewPersistence", row) == "/etc/cron.d/evil|M"

    def test_new_network_signature_prefers_capital_pid(self):
        row = {"remote_ip": "1.2.3.4", "remote_port": 443, "Pid": 7, "pid": 9}
        assert detectors.row_signature("Custom.Atlas.NewNetwork", row) == "1.2.3.4|443|7"

    def test_new_network_signature_falls_back_to_lower_pid(self):
        row = {"remote_ip": "1.2.3.4", "remote_port": 443, "pid": 9}
        assert detectors.row_signature("Custom.Atlas.NewNetwork", row) == "1.2.3.4|443|9"

    def test_yara_signature(self):
        row = {"pid": 5, "rule": "evilrule"}
        assert detectors.row_signature("Custom.Atlas.YaraProcess", row) == "5|evilrule"

    def test_unknown_detector_never_dedups(self):
        assert detectors.row_signature("Custom.Atlas.Nope", {"a": 1}) == ""


class TestSummaryParity:
    def test_new_process_summary(self):
        s = detectors.summarize_row("Custom.Atlas.NewProcess",
                                    {"image_path": "/tmp/x", "pid": 42})
        assert s == "New process not in baseline: /tmp/x (pid=42)"

    def test_new_persistence_summary(self):
        s = detectors.summarize_row("Custom.Atlas.NewPersistence", {"path": "/etc/cron.d/e"})
        assert s == "New persistence entry: /etc/cron.d/e"

    def test_new_network_summary(self):
        s = detectors.summarize_row("Custom.Atlas.NewNetwork",
                                    {"remote_ip": "1.2.3.4", "remote_port": 443, "Pid": 7})
        assert s == "New outbound connection: 1.2.3.4:443 (pid=7)"

    def test_yara_summary_quotes_rule(self):
        s = detectors.summarize_row("Custom.Atlas.YaraProcess",
                                    {"rule": "evil", "process_name": "bash", "pid": 5})
        assert s == "YARA hit 'evil' on process bash (pid=5)"

    def test_unknown_detector_summary_is_json(self):
        s = detectors.summarize_row("Custom.Atlas.Nope", {"a": 1})
        assert s.startswith("Custom.Atlas.Nope: ")
        assert '"a": 1' in s


class TestSeverityAndPivots:
    def test_severities(self):
        assert detectors.severity_of("Custom.Atlas.NewProcess") == "high"
        assert detectors.severity_of("Custom.Atlas.YaraProcess") == "high"
        assert detectors.severity_of("Custom.Atlas.NewNetwork") == "medium"
        assert detectors.severity_of("Custom.Atlas.NewPersistence") == "medium"
        assert detectors.severity_of("Custom.Atlas.Unknown") == "medium"

    def test_pivots_present_and_default_empty(self):
        assert detectors.pivots_for("Custom.Atlas.NewProcess")
        assert detectors.pivots_for("Custom.Atlas.Unknown") == []


class TestWindowsDetectors:
    def test_win_process_signature_and_summary(self):
        row = {"image_path": "C:\\evil.exe", "pid": 42, "started_utc": "T", "sha256": "ab"}
        assert detectors.row_signature("Custom.Atlas.WinNewProcess", row) == "C:\\evil.exe|42|T"
        assert detectors.summarize_row("Custom.Atlas.WinNewProcess", row) == \
            "New Windows process not in baseline: C:\\evil.exe (pid=42)"

    def test_win_network_signature_and_summary(self):
        row = {"remote_ip": "8.8.8.8", "remote_port": 53, "Pid": 9}
        assert detectors.row_signature("Custom.Atlas.WinNewNetwork", row) == "8.8.8.8|53|9"
        assert detectors.summarize_row("Custom.Atlas.WinNewNetwork", row) == \
            "New Windows outbound connection: 8.8.8.8:53 (pid=9)"

    def test_win_persistence_signature_and_summary(self):
        row = {"path": "HKLM\\...\\Run\\evil", "mtime_utc": "M"}
        assert detectors.row_signature("Custom.Atlas.WinNewPersistence", row) == \
            "HKLM\\...\\Run\\evil|M"
        assert detectors.summarize_row("Custom.Atlas.WinNewPersistence", row) == \
            "New Windows persistence entry: HKLM\\...\\Run\\evil"

    def test_win_process_template_carries_sha256(self):
        # SHA256 must survive rendering — the FirstSeenBinary behavior rule
        # (increment 6) keys on it.
        y = render.render_template("Custom.Atlas.WinNewProcess",
                                   {"image_paths": [], "process_names": []})
        assert "sha256" in y
        assert "watch_evtx" in y  # Sysmon real-time source present

    def test_win_persistence_template_uses_canonical_surface(self):
        y = render.render_template("Custom.Atlas.WinNewPersistence", {})
        for key in render.WIN_PERSISTENCE_SURFACE:
            # JSON-encoded into the VQL array (backslashes escaped).
            assert key.replace("\\", "\\\\") in y


class TestNormalizeOs:
    @pytest.mark.parametrize("raw,expected", [
        ("linux", "linux"), ("Linux", "linux"),
        ("windows", "windows"), ("Windows", "windows"), ("WINDOWS", "windows"),
        (None, "linux"), ("", "linux"), ("darwin", "linux"),
    ])
    def test_normalize(self, raw, expected):
        assert detectors.normalize_os(raw) == expected


class TestPlatformFilteredTemplates:
    def test_windows_filter_returns_only_windows(self):
        win = render.list_detector_templates(platform="windows")
        assert win == detectors.detectors_for_platform("windows")
        assert all("Win" in n for n in win)

    def test_linux_filter_excludes_windows(self):
        linux = render.list_detector_templates(platform="linux")
        assert linux == detectors.detectors_for_platform("linux")
        assert all("Win" not in n for n in linux)

    def test_filters_partition_all_templates(self):
        allt = set(render.list_detector_templates())
        assert (set(render.list_detector_templates(platform="linux"))
                | set(render.list_detector_templates(platform="windows"))) == allt


# ── OS-aware baseline_capture ────────────────────────────────────────────────

def _wire_velo(monkeypatch, os_system, results):
    import tools.velo as velo
    collected: list[str] = []

    def fake_client_info(client_id):
        return {"success": True, "rows": [{"os_info": {"system": os_system}}]}

    def fake_collect(client_id, artifact, parameters=None, **kw):
        collected.append(artifact)
        return {"success": True, "flow_id": f"F.{artifact}"}

    monkeypatch.setattr(velo, "client_info", fake_client_info)
    monkeypatch.setattr(velo, "collect_artifact", fake_collect)
    monkeypatch.setattr(velo, "wait_for_flow",
                        lambda *a, **k: {"success": True, "final_state": "FINISHED"})
    monkeypatch.setattr(velo, "get_collection_results",
                        lambda cid, fid, art: {"rows": results.get(art, [])})
    monkeypatch.setattr(velo, "upload_artifact_yaml", lambda y: {"success": True})
    return collected


class TestBaselineOsAware:
    def test_linux_baseline_stores_os_schema_and_pairs(self, tmp_path, monkeypatch):
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        results = {
            "Linux.Sys.Pslist": [
                {"Name": "bash", "Exe": "/bin/bash", "ParentName": "sshd"},
            ],
            monitor_mod.PERSISTENCE_SNAPSHOT_ARTIFACT: [{"path": "/etc/cron.d/x"}],
        }
        _wire_velo(monkeypatch, "linux", results)
        r = monitor_mod.baseline_capture("C.deadbeef", "DEMO-TEST")
        assert r["success"] and r["os"] == "linux"
        b = json.loads((tmp_path / "DEMO-TEST" / "monitoring" / "baselines"
                        / "C.deadbeef.json").read_text())
        assert b["os"] == "linux"
        assert b["baseline_schema_version"] == detectors.BASELINE_SCHEMA_VERSION
        assert b["parent_child_pairs"] == ["sshd>bash"]
        assert b["persistence_paths"] == ["/etc/cron.d/x"]

    def test_windows_baseline_collects_win_artifacts_and_win_persistence(
            self, tmp_path, monkeypatch):
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        win_persist = ["HKEY_LOCAL_MACHINE\\...\\Run\\OneDrive",
                       "C:\\Windows\\System32\\Tasks\\GoogleUpdate"]
        results = {
            "Windows.System.Pslist": [
                {"Name": "cmd.exe", "Exe": "C:\\Windows\\System32\\cmd.exe",
                 "ParentName": "explorer.exe"},
            ],
            monitor_mod.WIN_PERSISTENCE_SNAPSHOT_ARTIFACT: [
                {"path": p} for p in win_persist],
        }
        collected = _wire_velo(monkeypatch, "windows", results)
        r = monitor_mod.baseline_capture("C.deadbeef", "WIN-TEST")
        assert r["success"] and r["os"] == "windows"
        # Windows Pslist + the Windows persistence snapshot collected; the Linux
        # snapshot was NOT.
        assert "Windows.System.Pslist" in collected
        assert monitor_mod.WIN_PERSISTENCE_SNAPSHOT_ARTIFACT in collected
        assert monitor_mod.PERSISTENCE_SNAPSHOT_ARTIFACT not in collected
        b = json.loads((tmp_path / "WIN-TEST" / "monitoring" / "baselines"
                        / "C.deadbeef.json").read_text())
        assert b["os"] == "windows"
        assert sorted(b["persistence_paths"]) == sorted(win_persist)
        assert "explorer.exe>cmd.exe" in b["parent_child_pairs"]

    def test_client_info_failure_defaults_to_linux(self, tmp_path, monkeypatch):
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        results = {"Linux.Sys.Pslist": [], monitor_mod.PERSISTENCE_SNAPSHOT_ARTIFACT: []}
        collected = _wire_velo(monkeypatch, "linux", results)
        import tools.velo as velo
        monkeypatch.setattr(velo, "client_info",
                            lambda cid: (_ for _ in ()).throw(RuntimeError("boom")))
        r = monitor_mod.baseline_capture("C.deadbeef", "FALLBACK")
        assert r["success"] and r["os"] == "linux"
        assert "Linux.Sys.Pslist" in collected


# ── OS-aware start_watcher ───────────────────────────────────────────────────

class TestStartWatcherOsFiltering:
    def _baseline(self, tmp_path, monkeypatch, os_name, schema_version):
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        monitor_mod._ensure_layout("W-TEST")
        b = {
            "client_id": "C.deadbeef", "case_id": "W-TEST", "os": os_name,
            "baseline_schema_version": schema_version,
            "process_names": [], "image_paths": [], "persistence_paths": [],
            "endpoints": [], "yara_rules_path": "/rules/x.yar",
        }
        p = monitor_mod._baseline_path("W-TEST", "C.deadbeef")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(b))

    def _stub_spawn(self, monkeypatch):
        import tools.velo as velo
        monkeypatch.setattr(velo, "upload_artifact_yaml",
                            lambda y: {"success": True, "_atlas_call_id": 1})
        monkeypatch.setattr(velo, "update_client_event_table",
                            lambda *a, **k: {"success": True})

        class _FakeProc:
            pid = 4242

        monkeypatch.setattr(monitor_mod.subprocess, "Popen",
                            lambda *a, **k: _FakeProc())

    def test_windows_baseline_pushes_only_windows_detectors(self, tmp_path, monkeypatch):
        self._baseline(tmp_path, monkeypatch, "windows",
                       detectors.BASELINE_SCHEMA_VERSION)
        self._stub_spawn(monkeypatch)
        r = monitor_mod.start_watcher("C.deadbeef", "W-TEST")
        # Windows detectors exist → push them, never the Linux templates.
        assert r["success"] is True
        assert set(r["artifacts"]) == set(detectors.detectors_for_platform("windows"))
        assert all("Win" in a for a in r["artifacts"])

    def test_linux_baseline_pushes_linux_detectors(self, tmp_path, monkeypatch):
        self._baseline(tmp_path, monkeypatch, "linux",
                       detectors.BASELINE_SCHEMA_VERSION)
        self._stub_spawn(monkeypatch)
        r = monitor_mod.start_watcher("C.deadbeef", "W-TEST")
        assert r["success"] is True
        assert set(r["artifacts"]) == set(detectors.detectors_for_platform("linux"))
        assert r["warnings"] == []

    def test_stale_schema_warns(self, tmp_path, monkeypatch):
        self._baseline(tmp_path, monkeypatch, "linux", 1)
        self._stub_spawn(monkeypatch)
        r = monitor_mod.start_watcher("C.deadbeef", "W-TEST")
        assert r["success"] is True
        assert any("schema" in w for w in r["warnings"])
