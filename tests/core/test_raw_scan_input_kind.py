"""Byte scanners aimed at structured text.

The mirror of the existing wrong_input_kind checks: those stop a parser
being handed already-parsed text, this stops a raw scanner being handed
text a table tool should query. A raw scan of the run's own MFT CSV
exports reports success on every call while truncating what a table
query would answer.

The non-negotiable half of this behaviour is what must NOT be refused:
strings over disk images, memory, EVTX and hives is exactly right.
"""
from __future__ import annotations

import json

import pytest

from core import input_kind as ik


def _write(tmp_path, name, content: bytes):
    p = tmp_path / name
    p.write_bytes(content)
    return str(p)


CSV = (b"_host,FileName,FileSize\n"
       b"h1,Security.evtx,20971520\n"
       b"h1,Setup.evtx,65536\n"
       b"h1,System.evtx,2097152\n")


class TestRefusesStructuredText:
    def test_csv_is_refused(self, tmp_path):
        d = ik.refuse_raw_scan_of_structured_text(_write(tmp_path, "mft.csv", CSV))
        assert d and "structured text" in d["error"]
        assert "table" in d["use_instead"]

    def test_json_is_refused(self, tmp_path):
        path = _write(tmp_path, "x.json", b'{"a": 1, "b": [2, 3]}')
        assert ik.refuse_raw_scan_of_structured_text(path)

    def test_delimited_log_without_a_telling_extension(self, tmp_path):
        """Exported logs often land as .log — consistent separators are what
        make a column query possible, so that is what is detected."""
        body = b"".join(b"2031-02-03,10.0.0.1,443,allow\n" for _ in range(6))
        assert ik.refuse_raw_scan_of_structured_text(
            _write(tmp_path, "fw.log", body))


class TestLeavesRawScanningAlone:
    """These must keep working — this is the whole point of `strings`."""

    def test_binary_container_is_allowed(self, tmp_path):
        blob = bytes(range(256)) * 8
        assert ik.refuse_raw_scan_of_structured_text(
            _write(tmp_path, "disk.raw", blob)) is None

    def test_evtx_is_allowed(self, tmp_path):
        assert ik.refuse_raw_scan_of_structured_text(
            _write(tmp_path, "Security.evtx",
                   b"ElfFile\x00" + b"\x00" * 512)) is None

    def test_registry_hive_is_allowed(self, tmp_path):
        assert ik.refuse_raw_scan_of_structured_text(
            _write(tmp_path, "SYSTEM", b"regf" + b"\x00" * 512)) is None

    def test_freeform_prose_is_allowed(self, tmp_path):
        """Unstructured text has no columns to query — strings is fine."""
        note = b"Attacker used a remote access client then dumped credentials.\n" * 4
        assert ik.refuse_raw_scan_of_structured_text(
            _write(tmp_path, "notes.txt", note)) is None

    def test_missing_file_is_ignored(self, tmp_path):
        assert ik.refuse_raw_scan_of_structured_text(
            str(tmp_path / "gone.csv")) is None


class TestGateIntegration:
    def test_strings_grep_on_a_csv_raises_a_refusal(self, tmp_path):
        path = _write(tmp_path, "mft.csv", CSV)
        with pytest.raises(ValueError) as exc:
            ik.check_tool_input_kind("strings_strings_grep", {"path": path})
        payload = json.loads(str(exc.value))
        assert payload["gate"] == ik.GATE
        assert payload["param"] == "path"
        assert "table" in payload["use_instead"]

    def test_strings_grep_on_a_disk_image_is_untouched(self, tmp_path):
        path = _write(tmp_path, "disk.raw", bytes(range(256)) * 8)
        ik.check_tool_input_kind("strings_strings_grep", {"path": path})

    def test_an_unrelated_tool_is_untouched(self, tmp_path):
        path = _write(tmp_path, "mft.csv", CSV)
        ik.check_tool_input_kind("table_table_grep", {"path": path})

    def test_repeats_are_remembered(self, tmp_path):
        case = tmp_path / "case"
        (case / ".atlas").mkdir(parents=True)
        path = _write(tmp_path, "mft.csv", CSV)
        for _ in range(2):
            with pytest.raises(ValueError):
                ik.check_tool_input_kind(
                    "strings_strings_grep", {"path": path}, case_dir=case)
        assert ik.wrong_kind_count(case, "strings_strings_grep", path) >= 1
