"""Each long intake step after the fingerprinting replaces the run's status
line: the mount plan, every volume the contents index lists (minutes each on
a large one), the export join and the system baseline, and the record's time
moves with them. A listener that fails never stops the intake. Invented case
and image only (CASE-A, corp-ws01.raw, two partitions)."""
from __future__ import annotations

import ast
import json
import time
from pathlib import Path

import pytest

import core.execution_log as elog
from agent import cli
from core import contents_index as ci
from tests.core.test_contents_index import WS01, _MMLS_TWO, _fake_run, _image, _plan

ROOT = Path(__file__).resolve().parents[2]
PART = "Intake: indexing the contents of corp-ws01.raw, volume {} of 2"


@pytest.fixture
def case(tmp_path):
    root = tmp_path / "CASE-A"
    for d in ("evidence/disk", ".atlas", "analysis", "exports"):
        (root / d).mkdir(parents=True)
    elog.log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    _plan(root, [_image(root, "corp-ws01.raw")])
    return root


def _record(case: Path) -> dict:
    return json.loads((case / ".atlas" / "run_status.json").read_text(encoding="utf-8"))


def _stub(case: Path, monkeypatch, seen: list | None = None):
    """The executor for a two-partition image; with ``seen``, the run's
    record is read as each partition's listing starts."""
    fake = _fake_run({"corp-ws01.raw": WS01}, mmls={"corp-ws01.raw": _MMLS_TWO})

    def run(cmd, timeout):
        if seen is not None and cmd[0] == "fls":
            rec = _record(case)
            seen.append((rec["activity"], rec["updated_at"]))
        return fake(cmd, timeout)
    monkeypatch.setattr(ci, "_run", run)


def test_each_partition_the_index_lists_moves_the_runs_record(case, monkeypatch):
    real_gmtime = time.gmtime
    clock = iter(range(1924992000, 1924992000 + 36000, 60))      # 2031, one minute per write
    monkeypatch.setattr(time, "gmtime", lambda *_a: real_gmtime(next(clock)))
    seen: list = []
    _stub(case, monkeypatch, seen)
    intake = cli._IntakeStatus(case)
    first = _record(case)["updated_at"]
    built = ci.build(case, progress=intake.stage)
    assert built["listed"] == ["evidence/disk/corp-ws01.raw"]
    assert [a for a, _ in seen] == [PART.format(1), PART.format(2)]
    stamps = [first] + [u for _, u in seen]
    assert stamps == sorted(stamps) and len(set(stamps)) == 3, stamps
    assert _record(case)["stopped_reason"] == "running"


def test_an_image_kept_unchanged_lists_no_volume(case, monkeypatch):
    _stub(case, monkeypatch)
    ci.build(case)
    lines: list[str] = []
    assert ci.build(case, progress=lines.append)["kept"] == ["evidence/disk/corp-ws01.raw"]
    assert lines == ["joining the parsed exports to the listings"]


def test_a_failing_listener_never_stops_the_index(case, monkeypatch):
    _stub(case, monkeypatch)

    def broken(_text):
        raise RuntimeError("listener failed")
    assert ci.build(case, progress=broken)["listed"] == ["evidence/disk/corp-ws01.raw"]


def test_plane_a_names_its_later_steps_and_hands_the_listener_to_the_index(case, monkeypatch):
    got: dict = {}

    def build(case_dir, progress=None):
        got["progress"] = progress
        if progress is not None:
            progress("indexing the contents of corp-ws01.raw, volume 1 of 2")
        return {"listed": [], "kept": [], "failed": [], "exports": []}
    monkeypatch.setattr(ci, "build", build)
    from core.incremental import plane_a_scan
    lines: list[str] = []
    plane_a_scan(case, persist=True, trigger="test", write_journal=False, stage=lines.append)
    assert got["progress"] == lines.append
    assert lines.index("planning how to open the disk images") \
        < lines.index("indexing the contents of corp-ws01.raw, volume 1 of 2") \
        < lines.index("recording the system baseline")


def test_a_failing_listener_never_stops_plane_a(case, monkeypatch):
    """The dashboard starts a run with its stderr piped; a listener whose
    terminal line fails (a closed pipe) must not end the intake."""
    monkeypatch.setattr(ci, "build", lambda case_dir, progress=None: {
        "listed": [], "kept": [], "failed": [], "exports": []})
    from core.incremental import plane_a_scan
    heard: list[str] = []

    def broken(text):
        heard.append(text)
        raise BrokenPipeError(32, "Broken pipe")
    result = plane_a_scan(case, persist=True, trigger="test", write_journal=False, stage=broken)
    assert result.get("success") is True
    assert heard == ["planning how to open the disk images", "recording the system baseline"]


def test_both_intakes_hand_their_record_the_later_steps():
    tree = ast.parse((ROOT / "agent" / "cli.py").read_text(encoding="utf-8"))
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and getattr(n.func, "id", "") == "plane_a_scan"]
    assert len(calls) == 2
    for call in calls:
        given = {k.arg: ast.unparse(k.value) for k in call.keywords}
        # The intake's own listener, not a placeholder such as stage=None.
        assert "intake.stage" in given.get("stage", ""), ast.unparse(call)[:80]
