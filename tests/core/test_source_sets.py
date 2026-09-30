"""Partial coverage of an evidence series.

A series of rotated logs of which only a few were read, and a conclusion
about "the logs" drawn from those few.
Partial coverage is the dangerous case precisely because it looks finished.
"""
from __future__ import annotations

import json

from core import source_sets as ss


def _case(tmp_path, *, files=(), trace_cmds=()):
    (tmp_path / "analysis").mkdir(parents=True, exist_ok=True)
    for rel in files:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("data", encoding="utf-8")
    (tmp_path / "analysis" / "CASE_trace.json").write_text(
        json.dumps([{"type": "tool_call", "cmd": c} for c in trace_cmds]),
        encoding="utf-8")
    return tmp_path


WEEK = [f"evidence/firewall/2031-02-0{n}.log" for n in range(3, 10)] + [
    "evidence/firewall/2031-02-10.log"]


class TestSeriesDetection:
    def test_rotated_logs_form_one_series(self):
        groups = ss.group_series(WEEK)
        assert len(groups) == 1
        assert len(next(iter(groups.values()))) == 8

    def test_distinct_names_are_not_a_series(self):
        assert ss.group_series(
            ["evidence/dns1.log", "evidence/proxy2.log", "evidence/web3.log"]
        ) == {}

    def test_numbered_chunks_group(self):
        parts = [f"evidence/export/part{n:03d}.csv" for n in range(1, 6)]
        assert len(ss.group_series(parts)) == 1

    def test_a_pair_is_not_a_series(self):
        assert ss.group_series(WEEK[:2]) == {}

    def test_atlas_own_output_is_not_evidence(self):
        assert ss.series_key("analysis/tool-output/20310203T12_1") is None

    def test_names_without_digits_are_skipped(self):
        assert ss.series_key("evidence/firewall.log") is None

    def test_split_image_segments_are_one_unit_not_a_series(self):
        segments = [f"evidence/host/disk.E{n:02d}" for n in range(1, 5)]
        assert ss.group_series(segments) == {}
        assert ss.series_key("evidence/host/disk.Ex02") is None
        assert ss.series_key("evidence/host/logical.L01") is None


class TestPartialCoverage:
    def test_reading_two_of_eight_is_reported(self, tmp_path):
        case = _case(tmp_path, files=WEEK, trace_cmds=[
            "strings -a -n 8 evidence/firewall/2031-02-03.log",
            "grep x evidence/firewall/2031-02-08.log",
        ])
        partial = ss.partially_examined_series(case)
        assert len(partial) == 1
        assert partial[0]["examined"] == 2
        assert partial[0]["total"] == 8
        assert len(partial[0]["unexamined"]) == 6

    def test_a_fully_read_series_is_clean(self, tmp_path):
        case = _case(tmp_path, files=WEEK,
                     trace_cmds=[f"table_grep {p}" for p in WEEK])
        assert ss.partially_examined_series(case) == []

    def test_an_untouched_series_is_not_a_partial_set(self, tmp_path):
        """Nobody read any of it — that is an ordinary coverage gap, carried
        by the artifact-value and ledger obligations, not this one."""
        case = _case(tmp_path, files=WEEK, trace_cmds=["ls evidence"])
        assert ss.partially_examined_series(case) == []

    def test_empty_members_do_not_count_as_owed(self, tmp_path):
        case = _case(tmp_path, files=WEEK, trace_cmds=[
            f"table_grep {p}" for p in WEEK[:-1]])
        (tmp_path / WEEK[-1]).write_text("", encoding="utf-8")
        assert ss.partially_examined_series(case) == []

    def test_no_trace_means_no_verdict(self, tmp_path):
        case = _case(tmp_path, files=WEEK)
        assert ss.partially_examined_series(case) == []


class TestObligationAndNudge:
    def test_partial_series_blocks_complete(self, tmp_path):
        from core.investigation_obligations import list_obligations
        case = _case(tmp_path, files=WEEK, trace_cmds=[
            "strings evidence/firewall/2031-02-03.log"])
        unmet = {o["id"] for o in list_obligations(case) if not o["met"]}
        assert "evidence_sets_complete" in unmet

    def test_nudge_names_the_unread_members(self, tmp_path):
        case = _case(tmp_path, files=WEEK, trace_cmds=[
            "strings evidence/firewall/2031-02-03.log"])
        partial = ss.partially_examined_series(case)
        # The full set is available to callers...
        assert len(partial[0]["unexamined"]) == 7
        assert "evidence/firewall/2031-02-10.log" in partial[0]["unexamined"]
        # ...while the injected message stays bounded: the ratio tells the
        # model the size of the gap, the listing shows enough to act on.
        text = ss.format_series_nudge(partial)
        assert "1 of 8 examined" in text
        assert text.count("unexamined:") == 6
        assert "2031-02-04.log" in text

    def test_nothing_partial_means_no_message(self):
        assert ss.format_series_nudge([]) == ""


class TestResilience:
    def test_missing_case_is_inert(self, tmp_path):
        assert ss.partially_examined_series(tmp_path / "nope") == []
