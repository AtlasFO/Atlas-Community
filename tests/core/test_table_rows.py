"""The shared vocabulary of tabular results: the echo keys every reader
strips, the one time-column list, and the row time as one sortable string.
Fixtures are invented (CORP-WS01, jane.doe, dates in 2031)."""
from __future__ import annotations

import pathlib
import re

from core.table_rows import ECHO_KEYS, TIME_COLUMNS, row_time, time_columns

L2TCSV = ["date", "time", "timezone", "MACB", "source", "sourcetype", "type", "user",
          "host", "short", "desc", "version", "filename", "inode", "notes", "format", "extra"]
EVTXECMD = ["\ufeffRecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level",
            "Provider", "Channel", "ProcessId", "ThreadId", "Computer", "UserId", "MapDescription",
            "UserName", "RemoteHost", "PayloadData1", "ExecutableInfo", "SourceFile"]
MFTECMD = ["EntryNumber", "SequenceNumber", "InUse", "ParentEntryNumber", "FileName", "Extension",
           "FileSize", "Created0x10", "Created0x30", "LastModified0x10", "LastAccess0x10"]
PECMD = ["Note", "SourceFilename", "SourceCreated", "SourceModified", "SourceAccessed",
         "ExecutableName", "Hash", "Size", "Version", "RunCount", "LastRun", "PreviousRun0"]
RECMD = ["HivePath", "HiveType", "Description", "Category", "KeyPath", "ValueName", "ValueType",
         "ValueData", "LastWriteTimestamp", "PluginDetailFile"]
SIEM = ["startDateTime", "deviceDateTime", "logSourceIdentifier", "qidEventId", "userName"]
GENERIC = ["Computer", "EventTime", "Message"]


def test_the_echo_keys_cover_every_key_the_indicator_reader_stripped_before():
    from core import indicators
    legacy = {"query", "sanitized_query", "pattern", "patterns", "term", "terms", "keyword",
              "keywords", "search", "needle", "regex", "expression"}
    assert legacy <= ECHO_KEYS
    assert indicators.ECHO_KEYS is ECHO_KEYS
    assert {"terms_with_no_row", "terms_matched_not_returned", "terms_not_settled",
            "distribution"} <= ECHO_KEYS
    assert len(ECHO_KEYS) == 16


def test_the_time_column_of_each_published_tool_output():
    assert [L2TCSV[i] for i in time_columns(L2TCSV)] == ["date", "time"]
    assert [EVTXECMD[i] for i in time_columns(EVTXECMD)] == ["TimeCreated"]
    assert [MFTECMD[i] for i in time_columns(MFTECMD)] == ["Created0x10"]
    assert [PECMD[i] for i in time_columns(PECMD)] == ["LastRun"]
    assert [RECMD[i] for i in time_columns(RECMD)] == ["LastWriteTimestamp"]
    assert [SIEM[i] for i in time_columns(SIEM)] == ["startDateTime"]


def test_a_generic_header_needs_values_that_parse():
    rows = [["CORP-WS01", "2031-03-04 10:16:00", "logon jane.doe"],
            ["CORP-WS01", "2031-03-04T10:17:05.1234567", "logoff jane.doe"]]
    assert [GENERIC[i] for i in time_columns(GENERIC, rows)] == ["EventTime"]
    assert time_columns(GENERIC) == []
    assert time_columns(GENERIC, [["CORP-WS01", "Tuesday", "x"]]) == []
    assert time_columns(GENERIC, [["CORP-WS01", "", "x"]]) == []


def test_a_record_counter_is_not_a_time_column():
    assert "recordid" not in TIME_COLUMNS
    assert time_columns(["RecordId", "EventId", "Message"]) == []
    assert time_columns([]) == []


def test_the_row_time_is_one_iso_string():
    plaso = ["03/04/2031", "10:16:00", "UTC", "M...", "LOG", "Syslog"]
    assert row_time(plaso, time_columns(L2TCSV[:6])) == "2031-03-04T10:16:00"
    iso = ["12345", "67890", "2031-03-04T10:16:00.1234567", "4624"]
    assert row_time(iso, time_columns(EVTXECMD)) == "2031-03-04T10:16:00"
    assert row_time(["x", "y", "not a time", "4624"], [2]) == ""
    assert row_time(["x"], [5]) == ""
    assert row_time(["", ""], [0, 1]) == ""


def test_the_row_time_reads_a_12_hour_clock_an_offset_and_unpadded_dates():
    """Windows Event Viewer and SIEM exports write "3/4/2031 10:16:00 PM";
    an offset is converted to UTC, so a window or an order over rows of
    mixed offsets compares one clock."""
    assert row_time(["03/04/2031 10:16:00 PM"], [0]) == "2031-03-04T22:16:00"
    assert row_time(["3/4/2031 10:16:00 AM"], [0]) == "2031-03-04T10:16:00"
    assert row_time(["3/4/2031 12:05:00 AM"], [0]) == "2031-03-04T00:05:00"
    assert row_time(["2031-03-04T10:16:00+02:00"], [0]) == "2031-03-04T08:16:00"
    assert row_time(["2031-03-04T23:30:00-0230"], [0]) == "2031-03-05T02:00:00"
    assert row_time(["2031-03-04T10:16:00Z"], [0]) == "2031-03-04T10:16:00"
    assert row_time(["2031-03-04 10:16:00-10:48:00"], [0]) == "2031-03-04T10:16:00"
    assert row_time(["3/4/2031 13:00:00 PM"], [0]) == ""
    sample = [["Information", "3/4/2031 10:16:00 PM", "Security"]]
    assert time_columns(["Level", "Date and Time", "Source"], sample) == [1]


def test_the_module_imports_nothing_from_the_indicator_reader():
    """Checked at run time in a fresh interpreter, so a transitive import
    fails it too."""
    import subprocess
    import sys
    code = "import sys, core.table_rows; sys.exit('core.indicators' in sys.modules)"
    root = pathlib.Path(__file__).resolve().parents[2]
    assert subprocess.run([sys.executable, "-c", code], cwd=root).returncode == 0


def test_no_case_identifiers_are_baked_into_the_module():
    """The lists are format knowledge; no host, account, address or date of
    any case belongs in them."""
    src = pathlib.Path("core/table_rows.py").read_text()
    code = re.sub(r'"""(?:.|\n)*?"""', "", src)
    code = "\n".join(line for line in code.splitlines()
                      if not line.lstrip().startswith("#")).lower()
    assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", code)
    assert not re.search(r"\b20\d{2}-\d{2}-\d{2}\b", code)
    for token in ("corp-ws01", "jane.doe", "corp\\"):
        assert token not in code
