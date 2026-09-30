"""Tests for tools/bintriage.py — mocked binaries, graceful degradation."""
import pytest
from unittest.mock import patch

SAMPLE = "/evidence/suspect.exe"


class TestBinwalk:
    def test_scan_builds_command(self, run_ok):
        with patch("tools.bintriage.shutil.which", return_value="/usr/bin/binwalk"), \
             patch("tools.bintriage.run", return_value=run_ok) as m:
            from tools.bintriage import binwalk_scan
            binwalk_scan(SAMPLE, entropy=True)
        cmd = m.call_args[0][0]
        assert "binwalk" in cmd and "-E" in cmd and SAMPLE in cmd

    def test_missing_binary(self):
        with patch("tools.bintriage.shutil.which", return_value=None):
            from tools.bintriage import binwalk_scan
            r = binwalk_scan(SAMPLE)
        assert r["success"] is False and "binwalk" in r["error"]

    def test_extract_evidence_output_blocked(self):
        with patch("tools.bintriage.shutil.which", return_value="/usr/bin/binwalk"):
            from tools.bintriage import binwalk_extract
            with pytest.raises(Exception):
                binwalk_extract(SAMPLE, output_dir="/cases/x/evidence/out")


class TestUpx:
    def test_detect_packed(self):
        ok = {"success": True, "stdout": "tested 1 file [OK]", "stderr": "",
              "exit_code": 0}
        with patch("tools.bintriage.shutil.which", return_value="/usr/bin/upx"), \
             patch("tools.bintriage.run", return_value=ok):
            from tools.bintriage import upx_detect
            r = upx_detect(SAMPLE)
        assert r["upx_status"] == "upx-packed"

    def test_detect_not_packed(self):
        no = {"success": False, "stdout": "", "stderr": "NotPackedException",
              "exit_code": 2}
        with patch("tools.bintriage.shutil.which", return_value="/usr/bin/upx"), \
             patch("tools.bintriage.run", return_value=no):
            from tools.bintriage import upx_detect
            r = upx_detect(SAMPLE)
        assert r["upx_status"] == "not-upx-packed"


class TestTlsh:
    def test_missing_lib_or_hashes(self, tmp_path):
        # Either py-tlsh is absent (graceful error) or present (real hash of a
        # tiny file → too-small error). Both are success:False, never a crash.
        f = tmp_path / "a.bin"
        f.write_bytes(b"x" * 8)
        from tools.bintriage import tlsh_hash
        r = tlsh_hash(str(f))
        assert r["success"] is False
