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
    "2031-08-09 21:30:01 jroe connected to WAP\n"
    "interception traffic on 10.0.0.254 port 80\n"
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
        assert ei.search("jroe",
                         time_start="2031-08-09T00:00:00")["result_count"] >= 1
        assert ei.search("jroe",
                         time_start="2032-01-01T00:00:00")["result_count"] == 0

    def test_a_search_that_fills_its_limit_says_so(self, case_index):
        for cid in range(1, 4):
            ei.index_output(call_id=cid, tool="tcpdump", text=SAMPLE)
        full = ei.search("interception", max_results=2)
        assert full["result_count"] == 2 and full["hit_cap_reached"] is True
        assert ei.search("interception", max_results=50)["hit_cap_reached"] is False

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
        assert ei._parse_timestamp("x 2031-08-09T21:30:01 y") == \
            "2031-08-09T21:30:01"

    def test_plaso(self):
        assert ei._parse_timestamp("08/09/2031 21:30:01") == \
            "2031-08-09T21:30:01"

    def test_syslog_uses_reference_year(self):
        assert ei._parse_timestamp("Aug  9 21:30:01 host sshd",
                                   reference_year=2031) == \
            "2031-08-09T21:30:01"

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

    def test_an_iso_moment_to_the_minute_reads_with_or_without_t_and_zone(self):
        assert ei._parse_timestamp("at 2031-03-10 14:02 on CORP-WS01") == "2031-03-10T14:02:00"
        assert ei._parse_timestamp("2031-03-10T14:02") == "2031-03-10T14:02:00"
        assert ei._parse_timestamp("2031-03-10T14:02Z") == "2031-03-10T14:02:00"
        assert ei._parse_timestamp("2031-03-10 14:02+02:00") == "2031-03-10T12:02:00"
        assert ei._parse_timestamp("2031-03-10T14:02+0530") == "2031-03-10T08:32:00"

    def test_a_slashed_year_first_moment_reads_with_or_without_seconds(self):
        assert ei._parse_timestamp("2031/02/04 10:41:00") == "2031-02-04T10:41:00"
        assert ei._parse_timestamp("fw 2031/02/04 10:41:07.250 deny") == "2031-02-04T10:41:07"
        assert ei._parse_timestamp("2031/02/04T10:41:07-05:00") == "2031-02-04T15:41:07"
        assert ei._parse_timestamp("2031/02/04 10:41") == "2031-02-04T10:41:00"
        assert ei._parse_timestamp("2031/02/04 09:00-10:30") == "2031-02-04T09:00:00"
        assert ei._parse_timestamp("2031/02/04 10:41 then 2031-02-05 08:00:00") == "2031-02-05T08:00:00"
        assert ei._parse_timestamp("2031/13/04 10:41:00") is None

    def test_a_minute_span_is_not_read_as_an_offset(self):
        assert ei._parse_timestamp("between 2031-03-10 09:00-10:30 the host") == "2031-03-10T09:00:00"
        assert ei._parse_timestamp("2031-03-10T09:00-09:45") == "2031-03-10T09:00:00"
        assert ei._parse_timestamp("2031-03-10 09:00-0945") == "2031-03-10T09:00:00"
        assert ei._parse_timestamp("2031-03-10 10:00:00-05:00") == "2031-03-10T15:00:00"

    def test_a_moment_to_the_second_reads_as_before_beside_one_to_the_minute(self):
        assert ei._parse_timestamp("2031-03-09 08:00 then 2031-03-10 14:02:05") == "2031-03-10T14:02:05"
        assert ei._parse_timestamp("Mar 6 07:08:09 x 2031-03-10 14:02",
                                   reference_year=2031) == "2031-03-06T07:08:09"
        assert ei._parse_timestamp("2031-03-10 14:02:05-10:48:00") == "2031-03-10T14:02:05"
        assert ei._parse_timestamp("2031-03-10 14:0") is None


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

        def fake_index(call_id, tool, text, source_path="", reference_year=None):
            captured.update(call_id=call_id, tool=tool, text=text, reference_year=reference_year)
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


class TestAYearlessFormTakesTheEvidencesYear:
    """A month-day-clock form names no year. It takes the evidence file's
    modification date first (a log never carries a time after its last
    write: a month-day past the mtime's belongs to the year before), else
    the one year the same text states in its full-dated forms, else it is
    no moment at all; never the year the run happens in."""

    def test_without_a_year_it_is_no_moment(self):
        assert ei._parse_timestamp("Apr 21 15:32:08 host ftpd") is None
        assert ei.year_hint("Apr 21 15:32:08 host ftpd") is None

    def test_the_text_states_one_year_elsewhere_or_none(self):
        text = ("-rw-r--r-- 1 jane.doe staff 129875 Apr 21  2031 archive.zip\n"
                "-rw-r--r-- 1 jane.doe staff 41200 Apr 21 16:10 pic1.jpg\n")
        assert ei.year_hint(text) == 2031
        assert ei.year_hint("seen 2031-03-10 and later Mar 6 07:08:09") == 2031
        assert ei.year_hint("fw 2031/02/04 10:41 deny") == 2031 and ei.year_hint("03/04/2031 05:06:07") == 2031
        # Two years stated: none is the records' year (a certificate's
        # validity beside a listing).
        assert ei.year_hint("Not After: 2031-01-01\nlisted Apr 21  2030 archive.zip") is None
        # A tool banner's ctime form names no year for the records.
        assert ei.year_hint("Carver started at Wed Jun 04 09:00:00 2031\nApr 21 15:32:08 host ftpd") is None

    def test_the_evidence_date_comes_first_with_the_year_before_rule(self):
        from datetime import date
        assert ei._parse_timestamp("Apr 21 15:32:08 host ftpd", date(2031, 4, 30)) == "2031-04-21T15:32:08"
        # A month-day after the file's last write belongs to the year before.
        assert ei._parse_timestamp("Apr 21 15:32:08 host ftpd", date(2031, 3, 1)) == "2030-04-21T15:32:08"
        assert ei._parse_timestamp("Dec 31 23:59:59 host cron", date(2031, 1, 2)) == "2030-12-31T23:59:59"
        assert ei._parse_timestamp("Apr 21 15:32:08 host ftpd", 2029) == "2029-04-21T15:32:08"

    def test_index_output_dates_a_yearless_window_by_the_evidence_then_the_text_then_not_at_all(self, case_index):
        from datetime import date
        yearless = "Apr 21 15:32:08 host ftpd USER jane.doe\n" + "filler line about nothing\n" * 20
        banner = "Carver started at Wed Jun 02 08:00:00 2032\n"
        cert = "Not After: 2031-01-01\n"
        ei.index_output(call_id=1, tool="strings", text=yearless)
        ei.index_output(call_id=2, tool="strings", text=yearless + "listed Apr 21  2031 archive.zip\n")
        ei.index_output(call_id=3, tool="strings", text=yearless, reference_year=date(2030, 5, 1))
        # The banner trap: a run-year banner beside yearless lines names no
        # year; with the evidence date it is the evidence's year.
        ei.index_output(call_id=4, tool="strings", text=yearless + banner)
        ei.index_output(call_id=5, tool="strings", text=yearless + banner, reference_year=date(2030, 5, 1))
        # The certificate trap: the evidence date outranks a year the text
        # states; two stated years name none.
        ei.index_output(call_id=6, tool="strings", text=yearless + cert, reference_year=date(2030, 5, 1))
        ei.index_output(call_id=7, tool="strings", text=yearless + cert + "listed Apr 21  2029 archive.zip\n")
        con = sqlite3.connect(str(case_index / "evidence_index.db"))
        times = dict(con.execute(
            "SELECT s.call_id, w.event_time FROM sources s JOIN windows w ON w.source_id = s.source_id").fetchall())
        con.close()
        assert times == {1: None, 2: "2031-04-21T15:32:08", 3: "2030-04-21T15:32:08", 4: None,
                         5: "2030-04-21T15:32:08", 6: "2030-04-21T15:32:08", 7: None}

    def test_evidence_date_reads_the_evidence_files_mtime_and_never_an_export(self, case_index):
        import os
        import time
        from datetime import date
        root = case_index.parent
        (root / "evidence").mkdir()
        (root / "exports").mkdir()
        log = root / "evidence" / "auth.log"
        log.write_text("Apr 21 15:32:08 corp-ws01 sshd: session opened\n", encoding="utf-8")
        stamp = time.mktime((2031, 4, 26, 12, 0, 0, 0, 0, -1))
        os.utime(log, (stamp, stamp))
        out = root / "exports" / "auth.txt"
        out.write_text("x", encoding="utf-8")
        assert ei.evidence_date(["evidence/auth.log"]) == date(2031, 4, 26)
        assert ei.evidence_date([str(log)]) == date(2031, 4, 26)
        assert ei.evidence_date(["exports/auth.txt"]) is None
        assert ei.evidence_date(["evidence/missing.log"]) is None
