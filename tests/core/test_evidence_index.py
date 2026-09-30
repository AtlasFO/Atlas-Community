"""Per-case FTS5 evidence index (core/evidence_index.py).

The index makes accumulated tool output searchable: full text in, windows
with call_id lineage out. Concurrency contract: writes only from the server
process — these tests also pin the jobs_runner import-freedom that contract
depends on.
"""
import os
import sqlite3
from unittest.mock import patch

import pytest

from core import evidence_index as ei


@pytest.fixture
def case_index(tmp_path, monkeypatch):
    """Point the index at a temp analysis dir via a configured log."""
    analysis = tmp_path / "analysis"
    analysis.mkdir()
    monkeypatch.setattr(
        "core.evidence_index.db_path",
        lambda: str(analysis / "evidence_index.db"))
    return analysis


SAMPLE = (
    "2015-08-09 22:39:01 mr_evil connected to WAP\n"
    "interception traffic on 192.168.254.2 port 80\n"
    + "filler line about nothing in particular\n" * 60
)


class TestIngestAndSearch:
    def test_roundtrip_returns_the_right_call_id(self, case_index):
        ei.index_output(call_id=41, tool="tcpdump", text=SAMPLE)
        ei.index_output(call_id=42, tool="strings",
                        text="unrelated output " * 40)
        hits = ei.search("interception")
        assert hits["success"] is True
        assert hits["result_count"] >= 1
        assert all(r["call_id"] == 41 for r in hits["results"])
        assert "interception" in hits["results"][0]["snippet"]

    def test_event_time_extracted_and_filterable(self, case_index):
        ei.index_output(call_id=1, tool="tcpdump", text=SAMPLE)
        assert ei.search("mr_evil",
                         time_start="2015-08-09T00:00:00")["result_count"] >= 1
        assert ei.search("mr_evil",
                         time_start="2020-01-01T00:00:00")["result_count"] == 0

    def test_tool_filter(self, case_index):
        ei.index_output(call_id=1, tool="tcpdump", text=SAMPLE)
        assert ei.search("interception", tool="strings")["result_count"] == 0
        assert ei.search("interception", tool="tcpdump")["result_count"] >= 1

    def test_tiny_output_skipped(self, case_index):
        out = ei.index_output(call_id=1, tool="echo", text="short")
        assert out["status"] == "skipped_small"
        assert ei.stats()["sources"] == 0

    def test_no_case_configured_is_a_noop(self, monkeypatch):
        monkeypatch.setattr("core.evidence_index.db_path", lambda: None)
        assert ei.index_output(1, "t", SAMPLE)["status"] == "no_case"
        assert ei.search("anything")["success"] is False

    def test_per_source_cap(self, case_index, monkeypatch):
        monkeypatch.setattr(ei, "MAX_INDEXED_BYTES", 5000)
        out = ei.index_output(call_id=1, tool="bulk_extractor",
                              text="A" * 20000 + " needle")
        assert out["truncated"] is True
        # The needle beyond the cap must NOT be findable…
        assert ei.search("needle")["result_count"] == 0
        # …and the DB row records the truncation.
        conn = sqlite3.connect(ei.db_path())
        assert conn.execute(
            "SELECT truncated, byte_count FROM sources").fetchone() == (1, 5000)
        conn.close()

    def test_stats(self, case_index):
        ei.index_output(call_id=1, tool="tcpdump", text=SAMPLE)
        s = ei.stats()
        assert s["sources"] == 1 and s["windows"] >= 1
        assert s["tools"] == {"tcpdump": 1}


class TestQuerySanitizer:
    def test_pipe_becomes_or(self):
        assert ei._sanitize_fts5_query("cmd|powershell") == "cmd OR powershell"

    def test_special_chars_quoted(self):
        assert ei._sanitize_fts5_query("spinlock.exe") == '"spinlock.exe"'

    def test_operators_preserved(self):
        assert ei._sanitize_fts5_query("4624 AND logon") == "4624 AND logon"

    def test_hostile_query_does_not_error(self, case_index):
        ei.index_output(call_id=1, tool="t", text=SAMPLE)
        out = ei.search('"unclosed AND (foo* -bar')
        assert isinstance(out, dict)  # sanitized or reported, never raised


class TestTimestampParser:
    def test_iso(self):
        assert ei._parse_timestamp("x 2015-08-09T22:39:01 y") == \
            "2015-08-09T22:39:01"

    def test_plaso(self):
        assert ei._parse_timestamp("08/09/2015 22:39:01") == \
            "2015-08-09T22:39:01"

    def test_syslog_uses_reference_year(self):
        assert ei._parse_timestamp("Aug  9 22:39:01 host sshd",
                                   reference_year=2015) == \
            "2015-08-09T22:39:01"

    def test_none_when_absent(self):
        assert ei._parse_timestamp("no time here") is None


class TestQueryScanner:
    """What a scanner sees that a per-token test cannot. Each of these is a
    shape a model produces and FTS5 rejects outright."""

    def test_a_quote_that_never_closes_still_searches(self):
        assert ei._sanitize_fts5_query('"powershell -enc') == '"powershell -enc"'

    def test_a_trailing_operator_is_dropped_not_sent(self):
        """FTS5 rejects the whole query for a dangling AND; the terms before
        it are plainly what was meant."""
        assert ei._sanitize_fts5_query("mimikatz AND") == "mimikatz"
        assert ei._sanitize_fts5_query("OR lsass") == "lsass"

    def test_a_near_span_is_a_term_not_an_operator(self):
        """FTS5 spells proximity NEAR(a b, 3); a bare NEAR/3 sent through
        as an operator is a syntax error on the whole query."""
        assert ei._sanitize_fts5_query("lsass NEAR/3 dump") == 'lsass "NEAR/3" dump'

    def test_a_phrase_keeps_its_spaces(self):
        assert ei._sanitize_fts5_query('"failed logon"') == '"failed logon"'

    def test_a_quote_inside_a_term_is_escaped_not_passed_through(self):
        assert ei._sanitize_fts5_query('say"hi') == '"say""hi"'

    def test_an_empty_query_stays_empty(self):
        assert ei._sanitize_fts5_query("") == ""
        assert ei._sanitize_fts5_query("   ") == ""

    def test_an_empty_phrase_is_passed_through(self):
        # FTS5 accepts "" and matches nothing; search() reports that as no
        # results, not as a malformed query.
        assert ei._sanitize_fts5_query('""') == '""'


class TestTimestampPrecedence:
    """One table, one loop, and the first form found is the window's time.
    The order of trust is ISO-8601, then syslog, then a US-ordered date."""

    def test_iso_wins_over_a_later_syslog_line(self):
        assert ei._parse_timestamp("Mar 6 07:08:09 x 2021-01-02T03:04:05",
                                   reference_year=2021) == "2021-01-02T03:04:05"

    def test_syslog_wins_over_a_us_ordered_date(self):
        assert ei._parse_timestamp("01/02/2021 03:04:05 Mar 6 07:08:09",
                                   reference_year=2021) == "2021-03-06T07:08:09"

    def test_an_impossible_date_is_skipped_not_raised(self):
        assert ei._parse_timestamp("13/45/2015 99:99:99") is None
        assert ei._parse_timestamp("2021-13-04T05:06:07") is None

    def test_a_fractional_or_zoned_iso_moment_keeps_its_seconds(self):
        assert ei._parse_timestamp("2021-03-04T05:06:07.123456Z") == "2021-03-04T05:06:07"

    def test_a_us_ordered_date_needs_a_clock_after_whitespace(self):
        assert ei._parse_timestamp("03/04/2021 05:06:07") == "2021-03-04T05:06:07"
        assert ei._parse_timestamp("03/04/2021 no clock") is None


class TestExecutorHook:
    def test_indexing_failure_never_fails_the_tool_call(self, tmp_path):
        from core import executor
        result = {"cmd": ["strings", "x"], "success": True, "truncated": False,
                  "retries": 0, "exit_code": 0, "stderr": "",
                  "stdout": SAMPLE}
        with patch("core.evidence_index.index_output",
                   side_effect=RuntimeError("disk on fire")):
            # Must not raise.
            executor._index_output_best_effort(result, 7)

    def test_spill_file_preferred_over_capped_buffer(self, tmp_path,
                                                     monkeypatch):
        from core import executor
        spill = tmp_path / "big.stdout"
        spill.write_text("full spilled text " * 50)
        captured = {}

        def fake_index(call_id, tool, text, source_path=""):
            captured.update(call_id=call_id, tool=tool, text=text)
            return {"status": "indexed"}

        monkeypatch.setattr("core.evidence_index.index_output", fake_index)
        executor._index_output_best_effort(
            {"cmd": "tcpdump -r x", "stdout": "capped prefix",
             "stdout_file": str(spill)}, 9)
        assert captured["call_id"] == 9
        assert captured["tool"] == "tcpdump"
        assert captured["text"].startswith("full spilled text")


def test_jobs_runner_never_imports_the_index():
    """The single-writer-process contract: tools/jobs_runner.py runs as a
    separate process and must stay free of core imports (it says so in its
    own docstring — this pins the evidence_index part of that promise)."""
    src = open(os.path.join(os.path.dirname(__file__), "..", "..",
                            "tools", "jobs_runner.py")).read()
    assert "evidence_index" not in src
    assert "execution_log" not in src.replace(
        "It does NOT import core.execution_log", "")
