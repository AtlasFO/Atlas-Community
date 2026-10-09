"""Tests for tools/sleuthkit.py."""
import pytest
from unittest.mock import patch, MagicMock
import subprocess

IMG = "/mnt/ewf/ewf1"


@pytest.fixture(autouse=True)
def _images_need_not_exist(monkeypatch):
    """These tests build commands for images that are not on disk; the
    missing-image refusal is covered in test_sleuthkit_images.py."""
    monkeypatch.setattr("tools.sleuthkit._image_missing", lambda image: None)


@pytest.fixture(autouse=True)
def mock_run(run_ok):
    with patch("tools.sleuthkit.run", return_value=run_ok) as m:
        yield m


class TestPartitionTools:
    def test_tsk_mmls(self, mock_run):
        from tools.sleuthkit import tsk_mmls
        tsk_mmls(IMG)
        assert "mmls" in mock_run.call_args[0][0]

    def test_file_backed_tsk_tools_do_not_need_sudo(self, mock_run, tmp_path):
        """Privilege alignment: analysis/*.raw TSK reads must not force sudo."""
        from tools import sleuthkit as sk
        sk.tsk_mmls(IMG)
        assert mock_run.call_args[1].get("needs_sudo") is False
        sk.tsk_fsstat(IMG)
        assert mock_run.call_args[1].get("needs_sudo") is False
        sk.tsk_fls(IMG)
        assert mock_run.call_args[1].get("needs_sudo") is False
        sk.tsk_istat(IMG, 42)
        assert mock_run.call_args[1].get("needs_sudo") is False
        out = tmp_path / "inode.bin"
        sk.tsk_icat(IMG, 42, output_path=str(out))
        assert mock_run.call_args[1].get("needs_sudo") is False

    def test_tsk_mmstat(self, mock_run):
        from tools.sleuthkit import tsk_mmstat
        tsk_mmstat(IMG)
        assert "mmstat" in mock_run.call_args[0][0]

    def test_tsk_mmcat(self, mock_run):
        from tools.sleuthkit import tsk_mmcat
        tsk_mmcat(IMG, 1)
        cmd = mock_run.call_args[0][0]
        assert "mmcat" in cmd
        assert "1" in cmd


class TestFilesystemTools:
    def test_tsk_fsstat(self, mock_run):
        from tools.sleuthkit import tsk_fsstat
        tsk_fsstat(IMG)
        assert "fsstat" in mock_run.call_args[0][0]

    def test_tsk_fsstat_with_offset(self, mock_run):
        from tools.sleuthkit import tsk_fsstat
        tsk_fsstat(IMG, offset_sectors=2048)
        cmd = mock_run.call_args[0][0]
        assert "-o" in cmd
        assert "2048" in cmd

    def test_tsk_fls_recursive(self, mock_run):
        from tools.sleuthkit import tsk_fls
        tsk_fls(IMG, recursive=True)
        cmd = mock_run.call_args[0][0]
        assert "fls" in cmd
        assert "-r" in cmd

    def test_tsk_fls_bodyfile(self, mock_run):
        from tools.sleuthkit import tsk_fls
        tsk_fls(IMG, bodyfile=True)
        cmd = mock_run.call_args[0][0]
        assert "-m" in cmd

    def test_tsk_fls_deleted_only(self, mock_run):
        from tools.sleuthkit import tsk_fls
        tsk_fls(IMG, deleted_only=True)
        cmd = mock_run.call_args[0][0]
        assert "-d" in cmd


class TestInodeTools:
    def test_tsk_istat(self, mock_run):
        from tools.sleuthkit import tsk_istat
        tsk_istat(IMG, 42)
        cmd = mock_run.call_args[0][0]
        assert "istat" in cmd
        assert "42" in cmd

    def test_tsk_ils_orphan(self, mock_run):
        from tools.sleuthkit import tsk_ils
        tsk_ils(IMG, orphan_only=True)
        cmd = mock_run.call_args[0][0]
        assert "-p" in cmd

    def test_tsk_ffind(self, mock_run):
        from tools.sleuthkit import tsk_ffind
        tsk_ffind(IMG, 99)
        cmd = mock_run.call_args[0][0]
        assert "ffind" in cmd
        assert "99" in cmd


class TestIcatOutputSafety:
    def test_icat_blocked_on_evidence_path(self):
        from tools.sleuthkit import tsk_icat
        with pytest.raises(ValueError, match="protected evidence"):
            tsk_icat(IMG, "42", "/cases/example/evidence/out.bin")

    def test_icat_allowed_on_safe_path(self, tmp_path):
        from tools.sleuthkit import tsk_icat
        out = str(tmp_path / "extracted.bin")
        with patch("subprocess.Popen") as mock_popen:
            child = MagicMock(returncode=0)
            child.communicate.return_value = (None, b"")
            child.poll.return_value = 0
            mock_popen.return_value = child
            r = tsk_icat(IMG, "42", out)
        assert r["success"] is True


class TestBlockTools:
    def test_tsk_blkcat(self, mock_run):
        from tools.sleuthkit import tsk_blkcat
        tsk_blkcat(IMG, 1024)
        cmd = mock_run.call_args[0][0]
        assert "blkcat" in cmd
        assert "1024" in cmd

    def test_tsk_blkstat(self, mock_run):
        from tools.sleuthkit import tsk_blkstat
        tsk_blkstat(IMG, 512)
        assert "blkstat" in mock_run.call_args[0][0]

    def test_tsk_blkcalc(self, mock_run):
        from tools.sleuthkit import tsk_blkcalc
        tsk_blkcalc(IMG, 512)
        assert "blkcalc" in mock_run.call_args[0][0]

    def test_tsk_blkls_output_safe(self, mock_run):
        from tools.sleuthkit import tsk_blkls
        with pytest.raises(ValueError, match="protected evidence"):
            tsk_blkls(IMG, "/cases/example/evidence/blocks.raw")

    def test_tsk_blkls_allowed(self, tmp_path, mock_run):
        from tools.sleuthkit import tsk_blkls
        out = str(tmp_path / "blocks.raw")
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            tsk_blkls(IMG, out)


class TestTimelineTools:
    def test_tsk_mactime_basic(self, mock_run):
        from tools.sleuthkit import tsk_mactime
        tsk_mactime("bodyfile.txt")
        cmd = mock_run.call_args[0][0]
        assert "mactime" in cmd
        assert "-z" in cmd
        assert "UTC" in cmd

    def test_tsk_mactime_csv(self, mock_run):
        from tools.sleuthkit import tsk_mactime
        tsk_mactime("bodyfile.txt", csv_output=True)
        assert "-d" in mock_run.call_args[0][0]

    def test_tsk_mactime_date_filter(self, mock_run):
        from tools.sleuthkit import tsk_mactime
        tsk_mactime("bodyfile.txt", start_date="2018-01-01", end_date="2018-12-31")
        cmd = mock_run.call_args[0][0]
        assert "2018-01-01" in cmd


class TestHashAndSignatureTools:
    def test_tsk_hfind(self, mock_run):
        from tools.sleuthkit import tsk_hfind
        tsk_hfind("hashdb.txt", "deadbeef")
        cmd = mock_run.call_args[0][0]
        assert "hfind" in cmd
        assert "deadbeef" in cmd

    def test_tsk_sigfind(self, mock_run):
        from tools.sleuthkit import tsk_sigfind
        tsk_sigfind(IMG, "4D5A")
        cmd = mock_run.call_args[0][0]
        assert "sigfind" in cmd
        assert "4D5A" in cmd
        # Sleuthkit order: sigfind [opts] <hex> <image> — never image first
        # (image-first made sigfind treat "analysis/..." as hex → "Invalid
        # signature value: n").
        hex_i = cmd.index("4D5A")
        img_i = next(i for i, x in enumerate(cmd) if str(x).endswith(IMG) or IMG in str(x))
        assert hex_i < img_i


class TestJournalTools:
    def test_tsk_jls(self, mock_run):
        from tools.sleuthkit import tsk_jls
        tsk_jls(IMG)
        assert "jls" in mock_run.call_args[0][0]

    def test_tsk_jcat(self, mock_run):
        from tools.sleuthkit import tsk_jcat
        tsk_jcat(IMG, 5)
        cmd = mock_run.call_args[0][0]
        assert "jcat" in cmd
        assert "5" in cmd


_FAKE_INDXPARSE = """
import sys
from datetime import datetime


class NTATTR_DIRECTORY_INDEX_SLACK_ENTRY:
    def __init__(self, stamp):
        self._stamp = stamp

    def modified_time_safe(self):
        return self._stamp

    accessed_time_safe = changed_time_safe = created_time_safe = modified_time_safe

    def is_valid(self):
        return datetime(2024, 1, 1) > self._stamp > datetime(1990, 1, 1)


def main():
    entry = NTATTR_DIRECTORY_INDEX_SLACK_ENTRY(datetime(2031, 3, 14, 9, 30))
    print("args", sys.argv[1:], "listed", entry.is_valid())
"""


class TestTskIndxparse:
    @pytest.fixture
    def indxparse(self, tmp_path, monkeypatch):
        prog = tmp_path / "INDXParse.py"
        prog.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        prog.chmod(0o755)
        monkeypatch.setattr("tools.sleuthkit.tool_program",
                            lambda name: str(prog) if name == "INDXParse.py" else None)
        return str(prog)

    @pytest.fixture
    def stock(self, monkeypatch):
        """No indxparse package in this interpreter: the installed script runs."""
        import sys
        monkeypatch.setitem(sys.modules, "indxparse", None)

    @pytest.fixture
    def index(self, tmp_path):
        p = tmp_path / "analysis" / "CORP-WS01-users-I30.bin"
        p.parent.mkdir()
        p.write_bytes(b"INDX" + b"\x00" * 4092)
        return str(p)

    def test_indxparse_invokes_binary(self, mock_run, indxparse, stock, index):
        from tools.sleuthkit import tsk_indxparse
        res = tsk_indxparse(index)
        cmd = mock_run.call_args[0][0]
        # Upstream's CLI takes the input as a positional argument; it has no -f.
        assert cmd == [indxparse, "-d", index]
        assert res["slack_window"] == {"from": "1990-01-01", "to": "2024-01-01"}
        assert "no evidence that it never existed" in res["coverage_note"]

    def test_with_the_package_importable_the_window_ends_a_year_after_the_call(
            self, mock_run, indxparse, index, tmp_path, monkeypatch):
        import sys
        from datetime import date, timedelta
        fake = tmp_path / "fake" / "indxparse"
        fake.mkdir(parents=True)
        (fake / "__init__.py").write_text("", encoding="utf-8")
        monkeypatch.delitem(sys.modules, "indxparse", raising=False)
        monkeypatch.syspath_prepend(str(tmp_path / "fake"))
        from tools.sleuthkit import _INDX_RUNNER, tsk_indxparse
        res = tsk_indxparse(index)
        upper = (date.today() + timedelta(days=365)).isoformat()
        assert mock_run.call_args[0][0] == [sys.executable, _INDX_RUNNER, upper, "-d", index]
        assert res["slack_window"] == {"from": "1990-01-01", "to": upper}

    def test_a_failed_window_run_is_reported_not_retried_with_the_stock_window(
            self, mock_run, indxparse, index, monkeypatch):
        monkeypatch.setattr("tools.sleuthkit.importlib.util.find_spec", lambda name: object())
        mock_run.return_value = {"success": False, "stdout": "", "exit_code": 2,
                                 "stderr": "the installed indxparse lacks what this runner patches"}
        from tools.sleuthkit import tsk_indxparse
        res = tsk_indxparse(index)
        assert res["success"] is False and "slack_window" not in res
        assert mock_run.call_count == 1

    @pytest.mark.parametrize("head, says", [
        (b"FILE0" + b"\x00" * 1019, "ez.mftecmd"),
        (b"\x00" * 3 + b"NTFS    " + b"\x00" * 499 + b"\x55\xaa", "disk or volume image"),
        (b"PK\x03\x04" + b"\x01" * 508, "does not start with an INDX record"),
    ])
    def test_an_input_that_is_not_a_directory_index_is_refused_with_the_extraction_step(
            self, mock_run, indxparse, tmp_path, head, says):
        from tools.sleuthkit import tsk_indxparse
        p = tmp_path / "CORP-WS01.bin"
        p.write_bytes(head)
        res = tsk_indxparse(str(p))
        assert res["success"] is False and res["gate"] == "wrong_input_kind"
        assert says in res["error"] and "'<dir-inode>-160'" in res["error"]
        mock_run.assert_not_called()

    def test_a_missing_index_is_refused_as_missing_input(self, mock_run, indxparse):
        from tools.sleuthkit import tsk_indxparse
        res = tsk_indxparse("/tmp/CASE-A-no-such-index.bin")
        assert res["gate"] == "wrong_input_kind" and res["failure_class"] == "missing_input"
        mock_run.assert_not_called()

    def test_on_a_remote_host_the_stock_script_runs_unchecked(
            self, mock_run, indxparse, monkeypatch):
        """The file lives on the remote SIFT host and so does the program:
        nothing here can read the one or patch the other."""
        monkeypatch.setattr("core.remote.is_enabled", lambda: True)
        monkeypatch.setattr("tools.sleuthkit.importlib.util.find_spec", lambda name: object())
        from tools.sleuthkit import tsk_indxparse
        res = tsk_indxparse("/cases/CASE-A/analysis/remote-I30.bin")
        assert mock_run.call_args[0][0] == [indxparse, "-d", "/cases/CASE-A/analysis/remote-I30.bin"]
        assert res["slack_window"]["to"] == "2024-01-01"

    def test_a_copy_without_an_interpreter_line_runs_through_python(
            self, mock_run, tmp_path, monkeypatch, stock, index):
        """A package module copied as a file cannot be exec'd; the wrapper
        goes through program_argv, which runs it with the interpreter."""
        import sys
        prog = tmp_path / "INDXParse.py"
        prog.write_text("#    This file is part of a package.\n", encoding="utf-8")
        prog.chmod(0o755)
        monkeypatch.setattr("tools.sleuthkit.tool_program", lambda name: str(prog))
        from tools.sleuthkit import tsk_indxparse
        tsk_indxparse(index)
        assert mock_run.call_args[0][0] == [sys.executable, str(prog), "-d", index]

    def test_a_missing_indxparse_is_refused_without_running_anything(self, mock_run, monkeypatch):
        monkeypatch.setattr("tools.sleuthkit.tool_program", lambda name: None)
        from tools.sleuthkit import tsk_indxparse
        res = tsk_indxparse("/tmp/mft.bin")
        assert res["success"] is False and res["gate"] == "program_missing"
        assert "INDXParse.py" in res["error"]
        mock_run.assert_not_called()

    def test_indxparse_refuses_evidence_output(self):
        from tools.sleuthkit import tsk_indxparse
        with pytest.raises(ValueError):
            tsk_indxparse("/tmp/mft.bin", output_path="/mnt/host01/dump.txt")

    def test_indxparse_writes_output(self, mock_run, tmp_path, indxparse, index):
        from tools.sleuthkit import tsk_indxparse
        mock_run.return_value = {**mock_run.return_value, "success": True, "stdout": "indx data"}
        out = tmp_path / "analysis" / "indx.txt"
        tsk_indxparse(index, output_path=str(out))
        assert out.read_text() == "indx data"


class TestIndxparseWindowRunner:
    """The runner moves the upper bound of INDXParse's slack validity window
    and keeps its test; run against a stand-in package with the same names."""

    def _run(self, tmp_path, module_text, *args):
        import sys
        from tools.sleuthkit import _INDX_RUNNER
        pkg = tmp_path / "fake" / "indxparse"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "INDXParse.py").write_text(module_text, encoding="utf-8")
        return subprocess.run([sys.executable, _INDX_RUNNER, *args], capture_output=True,
                              text=True, env={"PYTHONPATH": str(tmp_path / "fake")}, timeout=60)

    def test_an_entry_inside_the_moved_window_is_listed(self, tmp_path):
        done = self._run(tmp_path, _FAKE_INDXPARSE, "2032-01-01", "-d", "x.bin")
        assert done.returncode == 0
        assert done.stdout.strip() == "args ['-d', 'x.bin'] listed True"

    def test_the_bound_still_filters(self, tmp_path):
        done = self._run(tmp_path, _FAKE_INDXPARSE, "2031-01-01", "-d", "x.bin")
        assert done.stdout.strip().endswith("listed False")

    def test_the_stock_window_drops_the_same_entry(self, tmp_path):
        import sys
        self._run(tmp_path, _FAKE_INDXPARSE, "2032-01-01")
        done = subprocess.run(
            [sys.executable, "-c", "from indxparse.INDXParse import main; main()"],
            capture_output=True, text=True, env={"PYTHONPATH": str(tmp_path / "fake")},
            timeout=60)
        assert done.stdout.strip().endswith("listed False")

    def test_a_package_without_the_patched_names_fails_loudly(self, tmp_path):
        done = self._run(tmp_path, "def main():\n    print('ran')\n", "2032-01-01", "-d", "x.bin")
        assert done.returncode == 2 and done.stdout == ""
        assert "NTATTR_DIRECTORY_INDEX_SLACK_ENTRY" in done.stderr
