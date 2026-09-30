"""Tests for tools/strings_tools.py."""
import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def mock_run(run_ok):
    with patch("tools.strings_tools.run", return_value=run_ok) as m:
        yield m


class TestStringsExtract:
    @pytest.fixture(autouse=True)
    def mock_path(self):
        with patch("tools.strings_tools.os.path.exists", return_value=True), \
             patch("core.paths.resolve_path_ci", side_effect=lambda p: (p, False)):
            yield

    def test_strings_extract_basic(self, mock_run):
        from tools.strings_tools import strings_extract
        strings_extract("/malware/sample.exe")
        cmd = mock_run.call_args[0][0]
        assert "strings" in cmd

    def test_min_length_applied(self, mock_run):
        from tools.strings_tools import strings_extract
        strings_extract("/malware/sample.exe", min_length=10)
        cmd = mock_run.call_args[0][0]
        assert "10" in cmd

    def test_output_path_evidence_blocked(self):
        from tools.strings_tools import strings_extract
        with pytest.raises(Exception):
            strings_extract("/malware/sample.exe", output_path="/cases/example/evidence/strings.txt")

    def test_output_path_safe(self, mock_run, tmp_path):
        from tools.strings_tools import strings_extract
        out = str(tmp_path / "strings.txt")
        strings_extract("/malware/sample.exe", output_path=out)
        assert mock_run.called


class TestStringsGrep:
    @pytest.fixture(autouse=True)
    def mock_path(self):
        with patch("tools.strings_tools.os.path.exists", return_value=True), \
             patch("core.paths.resolve_path_ci", side_effect=lambda p: (p, False)):
            yield

    def test_grep_pattern(self, mock_run):
        from tools.strings_tools import strings_grep
        mock_run.return_value = {**mock_run.return_value, "stdout": "http://evil.com\nftp://also.evil"}
        strings_grep("/malware/sample.exe", "http")
        assert mock_run.called

    def test_grep_runs_ascii_and_unicode_passes(self, mock_run):
        from tools.strings_tools import strings_grep
        strings_grep("/malware/sample.exe", "http")
        cmds = [c.args[0] for c in mock_run.call_args_list]
        assert len(cmds) == 2
        assert "-el" not in cmds[0]
        assert "-el" in cmds[1]

    def test_grep_matches_utf16le_only_strings(self, mock_run, run_ok):
        from tools.strings_tools import strings_grep

        def fake_run(cmd, **kw):
            if "-el" in cmd:
                return {**run_ok, "stdout": "http://utf16.evil\nnothing here"}
            return {**run_ok, "stdout": "plain ascii line"}

        mock_run.side_effect = fake_run
        result = strings_grep("/evidence/memdump.raw", "http")
        assert result["success"] is True
        assert result["match_count"] == 1
        assert result["ascii_match_count"] == 0
        assert result["unicode_match_count"] == 1
        assert result["matches"] == ["http://utf16.evil"]

    def test_grep_combines_both_encodings(self, mock_run, run_ok):
        from tools.strings_tools import strings_grep

        def fake_run(cmd, **kw):
            if "-el" in cmd:
                return {**run_ok, "stdout": "evil.com/unicode"}
            return {**run_ok, "stdout": "evil.com/ascii\nbenign"}

        mock_run.side_effect = fake_run
        result = strings_grep("/evidence/memdump.raw", r"evil\.com")
        assert result["match_count"] == 2
        assert result["ascii_match_count"] == 1
        assert result["unicode_match_count"] == 1
        assert result["matches"] == ["evil.com/ascii", "evil.com/unicode"]

    def test_grep_schema_backward_compatible(self, mock_run):
        from tools.strings_tools import strings_grep
        mock_run.return_value = {**mock_run.return_value, "stdout": "http://evil.com"}
        result = strings_grep("/malware/sample.exe", "http")
        for key in ("success", "file", "pattern", "match_count", "matches"):
            assert key in result

    def test_grep_invalid_regex(self, mock_run):
        from tools.strings_tools import strings_grep
        result = strings_grep("/malware/sample.exe", "http[")
        assert result["success"] is False
        assert "Invalid regex" in result["error"]

    def test_grep_both_passes_failed(self, mock_run, run_fail):
        from tools.strings_tools import strings_grep
        mock_run.return_value = run_fail
        mock_run.side_effect = None
        result = strings_grep("/malware/sample.exe", "http")
        assert result["success"] is False

    def test_grep_one_pass_failed_still_succeeds(self, mock_run, run_ok, run_fail):
        from tools.strings_tools import strings_grep

        def fake_run(cmd, **kw):
            if "-el" in cmd:
                return run_fail
            return {**run_ok, "stdout": "http://evil.com"}

        mock_run.side_effect = fake_run
        result = strings_grep("/malware/sample.exe", "http")
        assert result["success"] is True
        assert result["matches"] == ["http://evil.com"]


class TestFileIdentify:
    def test_file_identify(self, mock_run):
        from tools.strings_tools import file_identify
        file_identify("/malware/sample.exe")
        cmd = mock_run.call_args[0][0]
        assert "file" in cmd

    def test_file_identify_directory(self, mock_run, tmp_path):
        from tools.strings_tools import file_identify_directory
        file_identify_directory(str(tmp_path))
        cmd = mock_run.call_args[0][0]
        assert "file" in cmd


class TestHexdump:
    def test_hexdump_basic(self, mock_run):
        from tools.strings_tools import hexdump
        hexdump("/malware/sample.exe")
        cmd = mock_run.call_args[0][0]
        assert "hexdump" in cmd

    def test_hexdump_length(self, mock_run):
        from tools.strings_tools import hexdump
        hexdump("/malware/sample.exe", length=512)
        cmd = mock_run.call_args[0][0]
        assert "512" in cmd or any("512" in str(a) for a in cmd)

    def test_xxd_dump(self, mock_run):
        from tools.strings_tools import xxd_dump
        xxd_dump("/malware/sample.exe")
        cmd = mock_run.call_args[0][0]
        assert "xxd" in cmd


class TestExiftool:
    def test_exiftool_metadata(self, mock_run):
        from tools.strings_tools import exiftool_metadata
        exiftool_metadata("/evidence/document.pdf")
        cmd = mock_run.call_args[0][0]
        assert "exiftool" in cmd

    def test_exiftool_batch(self, mock_run, tmp_path):
        from tools.strings_tools import exiftool_batch
        exiftool_batch(str(tmp_path))
        assert "exiftool" in mock_run.call_args[0][0]


class TestStat:
    def test_stat_file(self, mock_run):
        from tools.strings_tools import stat_file
        stat_file("/malware/sample.exe")
        cmd = mock_run.call_args[0][0]
        assert "stat" in cmd


class TestResolvePathCI:
    def test_missing_file_returns_error(self, tmp_path):
        from tools.strings_tools import strings_extract
        result = strings_extract(str(tmp_path / "nonexistent.exe"))
        assert result["success"] is False
        assert "not found" in result["error"]
        assert "dumpfiles" in result["hint"]

    def test_case_corrected_path_used(self, tmp_path):
        real = tmp_path / "Staging" / "p.exe"
        real.parent.mkdir()
        real.write_bytes(b"MZ\x00test string here!!")
        from tools.strings_tools import strings_extract
        result = strings_extract(str(tmp_path / "staging" / "p.exe"))
        assert result["success"] is True
        assert result["path_resolved"] is not None

    def test_stderr_in_response(self, mock_run, tmp_path):
        mock_run.return_value = {**mock_run.return_value, "success": False, "stderr": "binary error"}
        real = tmp_path / "sample.exe"
        real.write_bytes(b"data")
        from tools.strings_tools import strings_extract
        result = strings_extract(str(real))
        assert "stderr" in result


class TestFlossExtract:
    def test_floss_missing_binary(self, monkeypatch):
        from tools.strings_tools import floss_extract
        monkeypatch.setattr("tools.strings_tools.shutil.which", lambda name: None)
        r = floss_extract("/tmp/x.exe")
        assert r["success"] is False
        assert "flare-floss" in r["error"]

    def test_floss_invokes_binary(self, monkeypatch):
        from tools.strings_tools import floss_extract
        monkeypatch.setattr("tools.strings_tools.shutil.which", lambda name: "/usr/local/bin/floss")
        captured = {}
        monkeypatch.setattr("tools.strings_tools.run",
                            lambda cmd, **kw: captured.setdefault("cmd", cmd) or {"success": True})
        floss_extract("/tmp/x.exe", min_length=10)
        assert captured["cmd"][0] == "/usr/local/bin/floss"
        assert "-n" in captured["cmd"]
        assert "10" in captured["cmd"]
        assert "/tmp/x.exe" in captured["cmd"]

    def test_floss_refuses_evidence_output_path(self):
        from tools.strings_tools import floss_extract
        with pytest.raises(ValueError):
            floss_extract("/tmp/x.exe", output_path="/mnt/host01/out.json")


def test_strings_grep_searches_many_patterns_in_one_pass(mock_run, tmp_path):
    """Extraction is the cost on a large input, so patterns share a pass.

    Three indicators over one disk image used to mean six full `strings`
    runs, each killed by the fixed default timeout.
    """
    from tools.strings_tools import strings_grep

    target = tmp_path / "sample.txt"
    target.write_text("x\n", encoding="utf-8")
    mock_run.return_value = {
        "success": True, "stderr": "", "exit_code": 0, "truncated": False,
        "cmd": "strings", "stdout": (
            "OneDrive sync client\nDropbox daemon started\nunrelated line\n"
        ),
    }

    res = strings_grep(str(target), ["OneDrive", "Dropbox", "FileZilla"])
    assert res["success"]
    # Both passes see the same stubbed output, so each pattern hits twice.
    assert res["matches_by_pattern"] == {
        "OneDrive": 2, "Dropbox": 2, "FileZilla": 0,
    }
    # One call, one extraction pair — not one pair per pattern.
    assert mock_run.call_count == 2

    mock_run.reset_mock()
    single = strings_grep(str(target), "OneDrive")
    assert single["pattern"] == "OneDrive"
    assert mock_run.call_count == 2


def test_strings_grep_timeout_scales_with_the_input(mock_run, tmp_path,
                                                    monkeypatch):
    """A fixed default killed every search over a disk image and returned
    nothing; the deadline has to follow the size of the input."""
    import core.paths as paths
    from core import DEFAULT_TIMEOUT
    from tools.strings_tools import strings_grep

    target = tmp_path / "sample.txt"
    target.write_text("x\n", encoding="utf-8")

    strings_grep(str(target), "x")
    assert mock_run.call_args.kwargs["timeout"] == DEFAULT_TIMEOUT

    monkeypatch.setattr(paths, "_input_size_bytes",
                        lambda _p: 40 * 1024 * 1024 * 1024)
    strings_grep(str(target), "x")
    assert mock_run.call_args.kwargs["timeout"] > DEFAULT_TIMEOUT
