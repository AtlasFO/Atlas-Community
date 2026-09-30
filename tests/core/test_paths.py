"""Tests for core/paths.py."""
import os
import pytest
from unittest.mock import patch
from core.paths import (
    is_evidence_path,
    assert_output_safe,
    reclaim_output_ownership,
    detect_case_id,
    parse_case_id_from_text,
    vol3_bin,
    vol3_symbols,
    ez_tool,
    OUTPUT_CAP,
)


class TestIsEvidencePath:
    @pytest.mark.parametrize("path,expected", [
        ("/cases/example/image.E01", True),
        ("/mnt/ewf_wkstn01/ewf1", True),
        ("/media/usb/image.dd", True),
        ("/home/analyst/cases/example/evidence/image.E01", True),
        ("/home/analyst/cases/example/mnt/ewf1", True),
        ("/home/analyst/cases/example/exports/result.csv", False),
        ("/home/analyst/cases/example/analysis/data.json", False),
        ("/home/analyst/cases/example/reports/report.md", False),
        ("/tmp/scratch.bin", False),
    ])
    def test_paths(self, path, expected):
        assert is_evidence_path(path) == expected


class TestAssertOutputSafe:
    def test_blocks_cases_prefix(self):
        with pytest.raises(ValueError, match="protected evidence"):
            assert_output_safe("/cases/example/output.csv")

    def test_blocks_mnt_prefix(self):
        with pytest.raises(ValueError, match="protected evidence"):
            assert_output_safe("/mnt/wkstn01/output.csv")

    def test_blocks_evidence_segment(self):
        with pytest.raises(ValueError, match="protected evidence"):
            assert_output_safe("/home/analyst/cases/example/evidence/out.csv")

    def test_blocks_case_local_mnt_segment(self, tmp_path):
        with pytest.raises(ValueError, match="protected evidence"):
            assert_output_safe(str(tmp_path / "mnt" / "out.csv"))

    def test_allows_analysis(self, tmp_path):
        safe = str(tmp_path / "analysis" / "out.csv")
        assert_output_safe(safe)  # should not raise

    def test_allows_exports(self, tmp_path):
        safe = str(tmp_path / "exports" / "out.csv")
        assert_output_safe(safe)

    def test_creates_the_parent_of_an_output_inside_the_case(self, tmp_path):
        out = tmp_path / "analysis" / "new" / "deeper" / "out.json"
        with patch("core.paths.active_case_dir", return_value=str(tmp_path)):
            assert_output_safe(str(out))
        assert out.parent.is_dir()
        assert not out.exists()

    def test_refuses_and_creates_nothing_outside_the_case(self, tmp_path):
        case = tmp_path / "case"
        case.mkdir()
        out = tmp_path / "elsewhere" / "out.json"
        with patch("core.paths.active_case_dir", return_value=str(case)), \
                patch("core.paths.output_roots", lambda c: [c]), \
                pytest.raises(ValueError):
            assert_output_safe(str(out))
        assert not out.parent.exists()

    def test_allows_reports(self, tmp_path):
        safe = str(tmp_path / "reports" / "out.md")
        assert_output_safe(safe)


class TestReclaimOutputOwnership:
    def test_chowns_the_tree_to_this_user_without_a_password_prompt(self, tmp_path):
        with patch("core.paths.subprocess.run") as run:
            run.return_value.returncode = 0
            assert reclaim_output_ownership(str(tmp_path)) is True
        argv = run.call_args[0][0]
        assert argv[:4] == ["sudo", "-n", "chown", "-R"]
        assert argv[4] == f"{os.getuid()}:{os.getgid()}"
        assert argv[5] == str(tmp_path)

    def test_a_missing_tree_or_a_failed_chown_reports_false(self, tmp_path):
        with patch("core.paths.subprocess.run") as run:
            assert reclaim_output_ownership(str(tmp_path / "absent")) is False
            run.assert_not_called()
            run.return_value.returncode = 1
            assert reclaim_output_ownership(str(tmp_path)) is False


class TestDetectCaseId:
    @pytest.mark.parametrize("text,expected", [
        ("**Case ID:** NITROBA-2008\n", "NITROBA-2008"),
        ("**Case ID**: CASE-A\n", "CASE-A"),
        ("| **Case ID** | CASE-C |\n", "CASE-C"),
        ("case_id: WS01\n", "WS01"),
    ])
    def test_parse_forms(self, text, expected):
        assert parse_case_id_from_text(text) == expected

    def test_template_bold_colon_in_case_md(self, tmp_path):
        (tmp_path / "CASE.md").write_text("**Case ID:** CASE-A\n")
        assert detect_case_id(tmp_path) == "CASE-A"

    def test_dir_basename_fallback(self, tmp_path):
        case = tmp_path / "cfreds-leak"
        case.mkdir()
        assert detect_case_id(case) == "cfreds-leak"


class TestVol3Bin:
    def test_returns_string(self):
        assert isinstance(vol3_bin(), str)

    def test_returns_vol_path(self):
        assert "vol" in vol3_bin()

    def test_env_override_wins(self, monkeypatch):
        monkeypatch.setenv("ATLAS_VOL3_BIN", "/opt/custom/vol")
        assert vol3_bin() == "/opt/custom/vol"

    def test_falls_back_to_path_lookup(self, monkeypatch, tmp_path):
        monkeypatch.delenv("ATLAS_VOL3_BIN", raising=False)
        fake_vol = tmp_path / "vol"
        fake_vol.write_text("#!/bin/sh\n")
        fake_vol.chmod(0o755)
        monkeypatch.setenv("PATH", str(tmp_path))
        assert vol3_bin() == str(fake_vol)

    def test_falls_back_to_sift_default_when_nothing_else_resolves(self, monkeypatch):
        monkeypatch.delenv("ATLAS_VOL3_BIN", raising=False)
        monkeypatch.setattr("shutil.which", lambda name: None)
        assert vol3_bin() == "/usr/local/bin/vol"


class TestVol3Symbols:
    def test_returns_default_when_env_unset(self, tmp_path, monkeypatch):
        monkeypatch.delenv("VOLATILITY_SYMBOLS", raising=False)
        path = vol3_symbols()
        assert "volatility3" in path
        assert os.path.isdir(path)

    def test_respects_env_override(self, tmp_path, monkeypatch):
        override = str(tmp_path / "custom_symbols")
        monkeypatch.setenv("VOLATILITY_SYMBOLS", override)
        path = vol3_symbols()
        assert path == override
        assert os.path.isdir(path)

    def test_creates_directory(self, tmp_path, monkeypatch):
        new_dir = str(tmp_path / "vol_syms" / "nested")
        monkeypatch.setenv("VOLATILITY_SYMBOLS", new_dir)
        vol3_symbols()
        assert os.path.isdir(new_dir)


class TestEzTool:
    def test_no_subdir(self):
        result = ez_tool("MFTECmd")
        assert "dotnet" in result
        assert "MFTECmd.dll" in result

    def test_with_subdir(self):
        result = ez_tool("EvtxECmd", subdir="EvtxeCmd")
        assert "EvtxeCmd" in result
        assert "EvtxECmd.dll" in result

    def test_base_path(self):
        result = ez_tool("RECmd", subdir="RECmd")
        assert "/opt/zimmermantools" in result


class TestOutputCap:
    def test_output_cap_is_50kb(self):
        assert OUTPUT_CAP == 51_200
