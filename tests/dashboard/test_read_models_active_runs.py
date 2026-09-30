"""Tests for dashboard/read_models.py's case-wide active_runs().

Bug this covers: the shell's "Atlas working" chip asked the *selected*
case's questions projection whether it was busy, so a run started in any
other case — or any run at all, before a case had been picked — left the
header reading "idle". active_runs() answers for every case under the
cases root at once, and carries the case names the chip's hover card lists.
"""
from __future__ import annotations

import json
import os

from dashboard import read_models

_DEAD_PID = 2**31 - 1  # not a real PID on any Linux system this runs on


def _make_case(root, name, **status):
    case_dir = root / name
    (case_dir / ".atlas").mkdir(parents=True, exist_ok=True)
    if status:
        (case_dir / ".atlas" / "run_status.json").write_text(
            json.dumps(status), encoding="utf-8")
    return case_dir


class TestActiveRuns:
    def test_reports_a_live_run_in_a_case_that_is_not_selected(self, tmp_path):
        # The whole point: nothing here says which case the viewer is on.
        _make_case(tmp_path, "alpha", case_id="ALPHA", pid=os.getpid(),
                   stopped_reason="running", activity="tsk_fls")
        _make_case(tmp_path, "beta")

        running = read_models.active_runs(str(tmp_path))

        assert [r["case_dir"] for r in running] == ["alpha"]
        assert running[0]["case_id"] == "ALPHA"
        assert running[0]["activity"] == "tsk_fls"

    def test_lists_every_running_case(self, tmp_path):
        _make_case(tmp_path, "alpha", case_id="ALPHA", pid=os.getpid(),
                   stopped_reason="running")
        _make_case(tmp_path, "beta", case_id="BETA", pid=os.getpid(),
                   stopped_reason="running")

        assert {r["case_dir"] for r in read_models.active_runs(str(tmp_path))} \
            == {"alpha", "beta"}

    def test_finished_and_dead_runs_are_not_reported(self, tmp_path):
        _make_case(tmp_path, "finished", case_id="F", pid=os.getpid(),
                   stopped_reason="completed")
        _make_case(tmp_path, "crashed", case_id="C", pid=_DEAD_PID,
                   stopped_reason="running")

        assert read_models.active_runs(str(tmp_path)) == []

    def test_case_id_falls_back_to_the_directory_name(self, tmp_path):
        # run_status.json written by an older build may carry no case_id.
        _make_case(tmp_path, "no-id", pid=os.getpid(), stopped_reason="running")

        assert read_models.active_runs(str(tmp_path))[0]["case_id"] == "no-id"

    def test_activity_drops_the_cli_only_prefix(self, tmp_path):
        # Legacy spinner prefix on older status files; UI wants the bare name.
        _make_case(tmp_path, "alpha", case_id="ALPHA", pid=os.getpid(),
                   stopped_reason="running", activity="\u23f5 img_vmdk_export_raw")

        assert read_models.active_runs(str(tmp_path))[0]["activity"] \
            == "img_vmdk_export_raw"

    def test_hidden_dirs_and_files_are_skipped(self, tmp_path):
        _make_case(tmp_path, ".hidden", case_id="H", pid=os.getpid(),
                   stopped_reason="running")
        (tmp_path / "loose.txt").write_text("not a case", encoding="utf-8")

        assert read_models.active_runs(str(tmp_path)) == []

    def test_one_unreadable_case_does_not_hide_the_others(self, tmp_path):
        # A corrupt run_status.json must not blank the indicator everywhere:
        # the chip is the only signal that a run is alive at all.
        _make_case(tmp_path, "alpha", case_id="ALPHA", pid=os.getpid(),
                   stopped_reason="running")
        broken = _make_case(tmp_path, "broken")
        (broken / ".atlas" / "run_status.json").write_text("{ not json",
                                                           encoding="utf-8")

        assert [r["case_dir"] for r in read_models.active_runs(str(tmp_path))] \
            == ["alpha"]

    def test_missing_cases_root_is_empty_not_an_error(self, tmp_path):
        assert read_models.active_runs(str(tmp_path / "nope")) == []
