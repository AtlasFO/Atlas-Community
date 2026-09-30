"""Increment 6 — watcher ↔ behavior-engine integration.

The behavior engine emits SyntheticAlerts under Behavior.* detector names; those
must flow through the watcher's existing _write_alert and produce well-formed
alert files (registry summary / severity / pivots), so the downstream
alert-waiter / check_alerts path needs no changes.
"""
import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def watcher():
    spec = importlib.util.spec_from_file_location(
        "atlas_velo_watcher", REPO / "bin" / "atlas-velo-watcher.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_write_alert_renders_behavior_alert(watcher, tmp_path):
    row = {"Hostname": "h1", "behavior_rule": "SpawnBurst", "entity": "bash",
           "observed": 9, "threshold": 8, "window_seconds": 60}
    path = watcher._write_alert(tmp_path, "CASE-X", "C.abc",
                                "Behavior.SpawnBurst", row)
    alert = json.loads(Path(path).read_text())
    assert alert["detector"] == "Behavior.SpawnBurst"
    assert alert["severity"] == "high"
    assert "spawn burst" in alert["summary"].lower()
    assert alert["suggested_pivot_tools"]           # registry pivots present
    assert alert["evidence"]["observed"] == 9


def test_consume_detector_writes_synthetic_alerts(watcher, tmp_path, monkeypatch):
    """A stubbed engine's synthetic alerts get written pre-dedup, without
    spawning velociraptor."""
    from monitoring import behavior

    # Fake velociraptor: a Popen whose stdout yields two process rows.
    rows = [
        json.dumps({"Hostname": "h", "image_path": "/bin/x", "process_name": "x",
                    "pid": "1", "parent_image": "bash"}),
        json.dumps({"Hostname": "h", "image_path": "/bin/y", "process_name": "y",
                    "pid": "2", "parent_image": "bash"}),
    ]

    class _FakeProc:
        def __init__(self):
            self.stdout = iter(rows)
            self.stderr = iter(())
            self.returncode = 0

        def poll(self):
            return 0

    monkeypatch.setattr(watcher.subprocess, "Popen", lambda *a, **k: _FakeProc())
    # No-op the stderr-drain thread.
    monkeypatch.setattr(watcher.threading, "Thread",
                        lambda *a, **k: type("T", (), {"start": lambda self: None,
                                                       "join": lambda self, timeout=None: None})())
    # The consume loop re-subscribes after the (finite) stdout drains; make the
    # reconnect sleep set the stop flag so the loop exits after one pass.
    monkeypatch.setattr(watcher.time, "sleep", lambda *_a: watcher._stop.set())

    class _Engine:
        def observe(self, detector, row):
            # Emit one synthetic alert on the second row.
            if row.get("pid") == "2":
                return [behavior.SyntheticAlert("Behavior.RareParentChild",
                        {**row, "entity": "bash>y", "behavior_rule": "RareParentChild"})]
            return []

    watcher._stop.clear()
    watcher._consume_detector("Custom.Atlas.NewProcess", "C.abc", "CASE-Y",
                              tmp_path, "velobin", str(tmp_path / "api.yaml"),
                              _Engine())

    written = sorted(p.name for p in tmp_path.glob("*.json"))
    # Two real NewProcess alerts + one synthetic RareParentChild alert.
    kinds = [json.loads((tmp_path / n).read_text())["detector"] for n in written]
    assert "Behavior.RareParentChild" in kinds
    assert kinds.count("Custom.Atlas.NewProcess") == 2
