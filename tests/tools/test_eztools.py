"""Tests for tools/eztools.py — Zimmerman .NET tools."""
import os

import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def mock_dotnet(run_ok):
    # _ez() refuses to run a tool whose .dll is absent, so resolution has to land
    # on a file that exists for the arg-building tests to reach run_dotnet at all.
    # This module's own path is a convenient always-present stand-in.
    with patch("tools.eztools.run_dotnet", return_value=run_ok) as m, \
            patch("tools.eztools._resolve_ez_dll", side_effect=lambda d: __file__):
        yield m


class TestMftEcmd:
    # _ez hard-refuses nonexistent -f/-d inputs before spawning (missing-input
    # gate), so arg-building tests need a real file on disk.
    @pytest.fixture
    def mft(self, tmp_path):
        p = tmp_path / "$MFT"
        p.write_bytes(b"FILE0" + b"\x00" * 32)
        return str(p)

    def test_mftecmd_basic(self, mock_dotnet, tmp_path, mft):
        from tools.eztools import ez_mftecmd
        ez_mftecmd(mft, str(tmp_path))
        args = mock_dotnet.call_args[0][1]
        assert "-f" in args
        assert "--csv" in args

    def test_mftecmd_output_dir(self, mock_dotnet, tmp_path, mft):
        from tools.eztools import ez_mftecmd
        out = str(tmp_path)
        ez_mftecmd(mft, out)
        args = mock_dotnet.call_args[0][1]
        assert out in args

    def test_mftecmd_slack(self, mock_dotnet, tmp_path, mft):
        from tools.eztools import ez_mftecmd
        ez_mftecmd(mft, str(tmp_path), include_slack=True)
        args = mock_dotnet.call_args[0][1]
        # --rs recovers FILE record slack; --ds dumps a security id and needs a value
        assert "--rs" in args and "--ds" not in args

    def test_mftecmd_defaults_add_nothing(self, mock_dotnet, tmp_path, mft):
        from tools.eztools import ez_mftecmd
        ez_mftecmd(mft, str(tmp_path))
        args = mock_dotnet.call_args[0][1]
        assert not {"--rs", "--ir", "--dr", "--re", "--rm"} & set(args)

    @pytest.mark.parametrize("mode,flags", [("inline", ["--ir"]), ("dump", ["--dr"]), ("both", ["--ir", "--dr"])])
    def test_mftecmd_resident_modes(self, mock_dotnet, tmp_path, mft, mode, flags):
        from tools.eztools import ez_mftecmd
        ez_mftecmd(mft, str(tmp_path), resident=mode, resident_ext=".ps1,.bat", resident_max_bytes=5_000_000)
        args = mock_dotnet.call_args[0][1]
        assert all(f in args for f in flags)
        if "--ir" in flags:
            assert args[args.index("--re") + 1] == ".ps1,.bat"
            assert args[args.index("--rm") + 1] == "1024000"     # MFTECmd's ceiling
        else:
            assert "--re" not in args and "--rm" not in args

    def test_mftecmd_refuses_an_unknown_resident_mode(self, mock_dotnet, tmp_path, mft):
        from tools.eztools import ez_mftecmd
        r = ez_mftecmd(mft, str(tmp_path), resident="everything")
        assert r["success"] is False and not mock_dotnet.called

    def test_mftecmd_dumps_no_content_under_a_handling_stop(self, mock_dotnet, tmp_path, mft):
        from tools.eztools import ez_mftecmd
        with patch("core.handling_stop.is_stopped", return_value=True), \
                patch("core.claim_graph.resolve_case_dir", return_value=str(tmp_path)):
            r = ez_mftecmd(mft, str(tmp_path), resident="dump")
            assert r["success"] is False and "handling stop" in r["error"] and not mock_dotnet.called
            ez_mftecmd(mft, str(tmp_path), resident="inline")
        assert "--ir" in mock_dotnet.call_args[0][1]


class TestMftEcmdUsnAndSum:
    def test_usn_with_and_without_the_mft(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_mftecmd_usn
        j = tmp_path / "$J"; j.write_bytes(b"x")
        m = tmp_path / "$MFT"; m.write_bytes(b"FILE0")
        ez_mftecmd_usn(str(j), output_dir=str(tmp_path))
        args = mock_dotnet.call_args[0][1]
        assert args[args.index("-f") + 1] == str(j) and "-m" not in args
        ez_mftecmd_usn(str(j), mft_path=str(m), output_dir=str(tmp_path))
        args = mock_dotnet.call_args[0][1]
        assert args[args.index("-m") + 1] == str(m)

    def test_sumecmd_reads_the_folder(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_sumecmd
        sum_dir = tmp_path / "Sum"; sum_dir.mkdir()
        ez_sumecmd(str(sum_dir), output_dir=str(tmp_path / "out"))
        args = mock_dotnet.call_args[0][1]
        assert args[:2] == ["-d", str(sum_dir)] and args[args.index("--csv") + 1] == str(tmp_path / "out")

    def test_sumecmd_refuses_a_missing_folder(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_sumecmd
        r = ez_sumecmd(str(tmp_path / "nope"), output_dir=str(tmp_path))
        assert r["success"] is False and r.get("gate") == "missing_input"


class TestEvtxEcmd:
    """ez_evtxecmd validates the input path before running, so these use a real
    directory rather than a notional /mnt path."""

    @pytest.fixture
    def logs(self, tmp_path):
        d = tmp_path / "Logs"
        d.mkdir()
        (d / "Security.evtx").write_bytes(b"ElfFile\x00")
        return str(d)

    def test_evtxecmd(self, mock_dotnet, logs, tmp_path):
        from tools.eztools import ez_evtxecmd
        ez_evtxecmd(logs, str(tmp_path / "out"))
        args = mock_dotnet.call_args[0][1]
        assert "--csv" in args

    def test_evtxecmd_event_ids_filter(self, mock_dotnet, logs, tmp_path):
        from tools.eztools import ez_evtxecmd
        ez_evtxecmd(logs, str(tmp_path / "out"), event_ids="4624,4625,4648")
        args = mock_dotnet.call_args[0][1]
        assert any("4624" in a for a in args)


class TestReCmd:
    def test_recmd_hive(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_recmd_hive
        hive = tmp_path / "SYSTEM"
        hive.write_bytes(b"regf" + b"\x00" * 32)
        ez_recmd_hive(str(hive), str(tmp_path))
        args = mock_dotnet.call_args[0][1]
        assert "--csv" in args

    def test_recmd_dir(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_recmd_dir
        cfg = tmp_path / "config"
        cfg.mkdir()
        (cfg / "SYSTEM").write_bytes(b"regf" + b"\x00" * 32)
        ez_recmd_dir(str(cfg), str(tmp_path))
        args = mock_dotnet.call_args[0][1]
        assert "-d" in args


class TestParserTools:
    def test_amcacheparser(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_amcacheparser
        hive = tmp_path / "Amcache.hve"
        hive.write_bytes(b"regf" + b"\x00" * 32)
        ez_amcacheparser(str(hive), str(tmp_path))
        args = mock_dotnet.call_args[0][1]
        assert "--csv" in args

    def test_appcompatcacheparser(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_appcompatcacheparser
        hive = tmp_path / "SYSTEM"
        hive.write_bytes(b"regf" + b"\x00" * 32)
        ez_appcompatcacheparser(str(hive), str(tmp_path))
        assert mock_dotnet.called

    def test_srumecmd(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_srumecmd
        db = tmp_path / "SRUDB.dat"
        db.write_bytes(b"\x00" * 4 + b"\xef\xcd\xab\x89" + b"\x00" * 24)
        hive = tmp_path / "SOFTWARE"
        hive.write_bytes(b"regf" + b"\x00" * 32)
        ez_srumecmd(str(db), str(tmp_path / "out"), software_hive=str(hive))
        args = mock_dotnet.call_args[0][1]
        assert args[:2] == ["-f", str(db)] and "--csv" in args
        assert args[args.index("-r") + 1] == str(hive)
        kape = tmp_path / "kape"
        kape.mkdir()
        ez_srumecmd(str(kape), str(tmp_path / "out2"))
        assert mock_dotnet.call_args[0][1][:2] == ["-d", str(kape)]
        (tmp_path / "parsed.csv").write_text("a,b\n")
        assert ez_srumecmd(str(tmp_path / "parsed.csv"), str(tmp_path / "out3"))["success"] is False

    def test_pecmd_prefetch(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_pecmd
        pf = tmp_path / "Prefetch"
        pf.mkdir()
        (pf / "CMD.EXE-1234ABCD.pf").write_bytes(b"SCCA")
        ez_pecmd(str(pf), str(tmp_path / "out"))
        args = mock_dotnet.call_args[0][1]
        assert "--csv" in args

    def test_jlecmd(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_jlecmd
        d = tmp_path / "AutomaticDestinations"
        d.mkdir()
        (d / "f01b4d95cf55d32a.automaticDestinations-ms").write_bytes(b"\x01")
        ez_jlecmd(str(d), str(tmp_path / "out"))
        assert mock_dotnet.called

    def test_rbcmd(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_rbcmd
        d = tmp_path / "$Recycle.Bin"
        d.mkdir()
        (d / "$IA1B2C3.txt").write_bytes(b"\x02")
        ez_rbcmd(str(d), str(tmp_path / "out"))
        assert mock_dotnet.called


# ── The exit-0-with-no-parsed-record family ──────────────────────────────────
#
# EvtxECmd/PECmd/JLECmd/LECmd/RBCmd exit 0 whatever they are handed: a
# directory with no parseable artifact, a corrupt artifact and an unsupported
# version all exit 0, and EvtxECmd and RBCmd write a HEADER-ONLY CSV while
# JLECmd and LECmd write nothing at all. Recorded as a success, any of those
# reads to an analyst as "the evidence is clean".
#
# What these tests pin down is the boundary: zero records is a REAL NEGATIVE when
# the tool had nothing to read or read something that held no records in scope,
# and a FAILURE only when candidate artifacts were present and none parsed.

def _writes_rows(names, rows=1, extra_stdout=""):
    """run_dotnet mock writing CSVs with `rows` data rows past the header."""
    def side_effect(dll, args, **kwargs):
        out = args[args.index("--csv") + 1]
        os.makedirs(out, exist_ok=True)
        for n in names:
            with open(os.path.join(out, n), "w") as fh:
                fh.write("Col1,Col2\n")
                fh.writelines(f"a{i},b{i}\n" for i in range(rows))
        return {"success": True, "stderr": "", "exit_code": 0, "truncated": False,
                "cmd": "ez",
                "stdout": f"Processed {rows} out of {rows} files\n{extra_stdout}"}
    return side_effect


def _writes_header_only(names, stdout):
    """EvtxECmd and RBCmd write the CSV header even when nothing parsed."""
    def side_effect(dll, args, **kwargs):
        out = args[args.index("--csv") + 1]
        os.makedirs(out, exist_ok=True)
        for n in names:
            with open(os.path.join(out, n), "w") as fh:
                fh.write("RecordNumber,TimeCreated,EventId\n")
        return {"success": True, "stdout": stdout, "stderr": "", "exit_code": 0,
                "truncated": False, "cmd": "ez"}
    return side_effect


def _writes_nothing(stdout):
    """JLECmd/LECmd/RBCmd write no CSV at all when nothing was processed."""
    def side_effect(dll, args, **kwargs):
        return {"success": True, "stdout": stdout, "stderr": "", "exit_code": 0,
                "truncated": False, "cmd": "ez"}
    return side_effect


class TestEvtxEcmdEmptyResult:
    """EvtxECmd always writes its CSV, so 'a file appeared' cannot be the test —
    only a row count can."""

    @pytest.fixture
    def logs(self, tmp_path):
        d = tmp_path / "Logs"
        d.mkdir()
        (d / "Security.evtx").write_bytes(b"ElfFile\x00")
        (d / "System.evtx").write_bytes(b"ElfFile\x00")
        return str(d)

    def test_rows_parsed_is_success(self, mock_dotnet, logs, out_dir):
        from tools.eztools import ez_evtxecmd
        mock_dotnet.side_effect = _writes_rows(["evtx.csv"], rows=2000)
        r = ez_evtxecmd(logs, out_dir)
        assert r["success"] is True
        assert "note" not in r

    def test_header_only_with_candidates_is_failure(self, mock_dotnet, logs, out_dir):
        """The bug: 2 .evtx present, tool read none, CSV holds only a header."""
        from tools.eztools import ez_evtxecmd
        mock_dotnet.side_effect = _writes_header_only(
            ["evtx.csv"], "Bogus.evtx is not an evtx file! Message: Invalid "
                          "signature! Expected 'ElfFile' Skipping...\n"
                          "Processed 0 files in 1.28 seconds")
        r = ez_evtxecmd(logs, out_dir)
        assert r["success"] is False
        assert "parsed nothing" in r["error"]
        assert "2 .evtx log(s) are present" in r["error"]

    def test_zero_events_in_scope_is_success_with_note(self, mock_dotnet, logs, out_dir):
        """A log filtered with --inc for an event ID it does not hold gives a
        header-only CSV but 'Processed 1 file'. The log was read and held
        nothing matching — a true negative, and it must not be reported as a
        failure."""
        from tools.eztools import ez_evtxecmd
        mock_dotnet.side_effect = _writes_header_only(
            ["evtx.csv"], "Metrics (including dropped events)\nEvent ID\tCount\n"
                          "Processed 1 file in 3.01 seconds")
        r = ez_evtxecmd(logs, out_dir, event_ids="31337")
        assert r["success"] is True
        assert "records in scope" in r["note"]

    def test_no_evtx_present_is_success_with_note(self, mock_dotnet, tmp_path, out_dir):
        """A directory holding no .evtx at all is a true negative, not a failure."""
        from tools.eztools import ez_evtxecmd
        empty = tmp_path / "Logs"
        empty.mkdir()
        mock_dotnet.side_effect = _writes_header_only(
            ["evtx.csv"], "Processed 0 files in 1.27 seconds")
        r = ez_evtxecmd(str(empty), out_dir)
        assert r["success"] is True
        assert "nothing to" in r["note"]

    def test_partial_parse_is_success_with_warning(self, mock_dotnet, logs, out_dir):
        """A truncated log still yields the records before the damage. Those
        rows are evidence, but the analyst has to know the parse was
        incomplete."""
        from tools.eztools import ez_evtxecmd
        mock_dotnet.side_effect = _writes_rows(
            ["evtx.csv"], rows=100,
            extra_stdout="Files with errors\n/logs/Security.evtx error count: 1")
        r = ez_evtxecmd(logs, out_dir)
        assert r["success"] is True
        assert "only the files that parsed" in r["note"]

    def test_missing_path_rejected(self, mock_dotnet, tmp_path, out_dir):
        from tools.eztools import ez_evtxecmd
        missing = tmp_path / "nope"
        r = ez_evtxecmd(str(missing), out_dir)
        assert r["success"] is False
        # Two gates can refuse this, and they word it differently: the EVTX
        # input-kind gate says "does not exist", the generic dispatch says
        # "path not found". Assert the substance — the refusal names the
        # offending path and the tool never ran — so the test does not break
        # again the next time a message is improved.
        assert str(missing) in r["error"]
        assert not mock_dotnet.called


class TestPecmdEmptyResult:
    """These pin the wrapper's logic against the reporting PECmd shares with
    its siblings (same codebase family, same 'Processed X out of Y files' /
    'Found 0 files' reporting). The empty-Prefetch case is the true negative
    that matters."""

    @pytest.fixture
    def prefetch(self, tmp_path):
        d = tmp_path / "Prefetch"
        d.mkdir()
        (d / "CMD.EXE-1234ABCD.pf").write_bytes(b"SCCA")
        (d / "AUDIOD~1.PF").write_bytes(b"SCCA")   # real 8.3 name, uppercase
        return str(d)

    def test_rows_parsed_is_success(self, mock_dotnet, prefetch, out_dir):
        from tools.eztools import ez_pecmd
        mock_dotnet.side_effect = _writes_rows(["prefetch.csv"], rows=176)
        r = ez_pecmd(prefetch, out_dir)
        assert r["success"] is True

    def test_pf_present_but_none_parsed_is_failure(self, mock_dotnet, prefetch, out_dir):
        from tools.eztools import ez_pecmd
        mock_dotnet.side_effect = _writes_nothing("Found 0 files")
        r = ez_pecmd(prefetch, out_dir)
        assert r["success"] is False
        assert "2 .pf file(s) are present" in r["error"]

    def test_empty_prefetch_dir_is_success_with_note(self, mock_dotnet, tmp_path, out_dir):
        """A Prefetch directory with no .pf in it is a real finding — prefetching
        may be disabled, or the files wiped. It is NOT a tool failure, and the
        note points at how to corroborate."""
        from tools.eztools import ez_pecmd
        d = tmp_path / "Prefetch"
        d.mkdir()
        mock_dotnet.side_effect = _writes_nothing("Found 0 files")
        r = ez_pecmd(str(d), out_dir)
        assert r["success"] is True
        assert "nothing to" in r["note"]

class TestJlecmdEmptyResult:
    @pytest.fixture
    def jl(self, tmp_path):
        d = tmp_path / "AutomaticDestinations"
        d.mkdir()
        (d / "f01b4d95cf55d32a.automaticDestinations-ms").write_bytes(b"\x01")
        return str(d)

    def test_renamed_output_is_credited(self, mock_dotnet, jl, out_dir):
        """JLECmd splits output by type and renames --csvf to
        '<name>_AutomaticDestinations.csv', so a check for output_file would
        never find it."""
        from tools.eztools import ez_jlecmd
        mock_dotnet.side_effect = _writes_rows(
            ["jumplists_AutomaticDestinations.csv",
             "jumplists_CustomDestinations.csv"], rows=8)
        r = ez_jlecmd(jl, out_dir)
        assert r["success"] is True
        assert len(r["output_paths"]) == 2

    def test_jumplists_present_but_none_parsed_is_failure(self, mock_dotnet, jl, out_dir):
        from tools.eztools import ez_jlecmd
        mock_dotnet.side_effect = _writes_nothing("Found 0 files")
        r = ez_jlecmd(jl, out_dir)
        assert r["success"] is False
        assert "1 jump list(s) are present" in r["error"]

    def test_no_jumplists_present_is_success_with_note(self, mock_dotnet, tmp_path, out_dir):
        from tools.eztools import ez_jlecmd
        d = tmp_path / "Recent"
        d.mkdir()
        mock_dotnet.side_effect = _writes_nothing("Found 0 files")
        r = ez_jlecmd(str(d), out_dir)
        assert r["success"] is True
        assert "nothing to" in r["note"]

class TestLecmdEmptyResult:
    @pytest.fixture
    def recent(self, tmp_path):
        d = tmp_path / "Recent"
        d.mkdir()
        (d / "The Internet.lnk").write_bytes(b"L\x00\x00\x00")
        return str(d)

    def test_rows_parsed_is_success(self, mock_dotnet, recent, out_dir):
        from tools.eztools import ez_lecmd
        mock_dotnet.side_effect = _writes_rows(["lnk.csv"], rows=2)
        assert ez_lecmd(recent, out_dir)["success"] is True

    def test_lnk_present_but_none_parsed_is_failure(self, mock_dotnet, recent, out_dir):
        """A file with a bad LNK signature produces a 'Failed files' section,
        exit 0 and no CSV."""
        from tools.eztools import ez_lecmd
        mock_dotnet.side_effect = _writes_nothing(
            "Failed files\n  Bogus.lnk ==> (has an invalid signature! Is it a "
            "valid LNK file?)")
        r = ez_lecmd(recent, out_dir)
        assert r["success"] is False
        assert "1 .lnk shortcut(s) are present" in r["error"]

    def test_no_lnk_present_is_success_with_note(self, mock_dotnet, tmp_path, out_dir):
        from tools.eztools import ez_lecmd
        d = tmp_path / "Recent"
        d.mkdir()
        mock_dotnet.side_effect = _writes_nothing("Found 0 files")
        r = ez_lecmd(str(d), out_dir)
        assert r["success"] is True
        assert "nothing to" in r["note"]

class TestRbcmdEmptyResult:
    @pytest.fixture
    def bin_dir(self, tmp_path):
        d = tmp_path / "$Recycle.Bin" / "S-1-5-21-1001"
        d.mkdir(parents=True)
        (d / "$IA1B2C3.txt").write_bytes(b"\x02")
        return str(tmp_path / "$Recycle.Bin")

    def test_rows_parsed_is_success(self, mock_dotnet, bin_dir, out_dir):
        from tools.eztools import ez_rbcmd
        mock_dotnet.side_effect = _writes_rows(["recyclebin.csv"], rows=2)
        assert ez_rbcmd(bin_dir, out_dir)["success"] is True

    def test_header_only_with_candidate_is_failure(self, mock_dotnet, bin_dir, out_dir):
        """RBCmd writes a header-only CSV when a $I record will not parse (an
        NTFS $I30 handed to it is one such input), so rows have to be checked."""
        from tools.eztools import ez_rbcmd
        mock_dotnet.side_effect = _writes_header_only(
            ["recyclebin.csv"], "Failed files\n  $IA1B2C3.txt")
        r = ez_rbcmd(bin_dir, out_dir)
        assert r["success"] is False
        assert "1 $I Recycle Bin record(s) are present" in r["error"]

    def test_empty_recycle_bin_is_success_with_note(self, mock_dotnet, tmp_path, out_dir):
        """An empty Recycle Bin is a normal state, not a tool failure."""
        from tools.eztools import ez_rbcmd
        d = tmp_path / "$Recycle.Bin"
        d.mkdir()
        mock_dotnet.side_effect = _writes_nothing("Found 0 files. Processing...")
        r = ez_rbcmd(str(d), out_dir)
        assert r["success"] is True
        assert "nothing to" in r["note"]

    def test_ntfs_i30_is_not_counted_as_a_recycle_record(self, mock_dotnet, tmp_path, out_dir):
        """'$I30' is an NTFS index attribute, not a Recycle Bin record, and
        extracted directory trees hold many of them. Counting them as candidates
        would turn every directory containing one into a spurious failure."""
        from tools.eztools import ez_rbcmd
        d = tmp_path / "$Recycle.Bin"
        d.mkdir()
        (d / "$I30").write_bytes(b"INDX")
        mock_dotnet.side_effect = _writes_nothing("Found 0 files. Processing...")
        r = ez_rbcmd(str(d), out_dir)
        assert r["success"] is True
        assert "nothing to" in r["note"]

class TestBstrings:
    """bstrings has no --csv/--csvf (its only output flag is -o), and its own
    -f/-d flags are broken upstream — the target is fed on stdin instead."""

    @pytest.fixture
    def target(self, tmp_path):
        p = tmp_path / "evidence.bin"
        p.write_bytes(b"a string worth finding\nanother one here\n")
        return str(p)

    @pytest.fixture
    def out_dir(self, tmp_path):
        d = tmp_path / "analysis"
        d.mkdir()
        return str(d)

    @staticmethod
    def _writes(hits, **overrides):
        """Mock run_dotnet that creates the -o file bstrings would write."""
        def side_effect(dll, args, **kwargs):
            out = args[args.index("-o") + 1]
            with open(out, "w") as fh:
                fh.writelines(f"hit {i}\n" for i in range(hits))
            return {"success": True, "stdout": "Searching 1 chunk", "stderr": "",
                    "exit_code": 0, "truncated": False, "cmd": "bstrings",
                    **overrides}
        return side_effect

    def test_uses_o_not_csv(self, mock_dotnet, target, out_dir):
        from tools.eztools import ez_bstrings
        mock_dotnet.side_effect = self._writes(2)
        ez_bstrings(target, out_dir)
        args = mock_dotnet.call_args[0][1]
        assert "--csv" not in args
        assert "--csvf" not in args
        assert "-o" in args
        assert args[args.index("-o") + 1] == os.path.join(out_dir, "bstrings.txt")

    def test_target_fed_on_stdin_not_dash_f(self, mock_dotnet, target, out_dir):
        from tools.eztools import ez_bstrings
        mock_dotnet.side_effect = self._writes(2)
        ez_bstrings(target, out_dir)
        args = mock_dotnet.call_args[0][1]
        assert "-f" not in args and "-d" not in args
        assert mock_dotnet.call_args[1]["stdin_path"] == target

    def test_default_output_is_txt_not_csv(self, mock_dotnet, target, out_dir):
        from tools.eztools import ez_bstrings
        mock_dotnet.side_effect = self._writes(1)
        r = ez_bstrings(target, out_dir)
        assert r["output_path"].endswith("bstrings.txt")

    def test_min_length_and_pattern(self, mock_dotnet, target, out_dir):
        from tools.eztools import ez_bstrings
        mock_dotnet.side_effect = self._writes(1)
        ez_bstrings(target, out_dir, min_length=12, pattern="email")
        args = mock_dotnet.call_args[0][1]
        assert args[args.index("-m") + 1] == "12"
        assert args[args.index("--lr") + 1] == "email"

    def test_no_pattern_omits_lr(self, mock_dotnet, target, out_dir):
        from tools.eztools import ez_bstrings
        mock_dotnet.side_effect = self._writes(1)
        ez_bstrings(target, out_dir)
        assert "--lr" not in mock_dotnet.call_args[0][1]

    def test_counts_hits(self, mock_dotnet, target, out_dir):
        from tools.eztools import ez_bstrings
        mock_dotnet.side_effect = self._writes(7)
        r = ez_bstrings(target, out_dir)
        assert r["success"] is True
        assert r["hits"] == 7

    def test_zero_hits_is_success_with_note(self, mock_dotnet, target, out_dir):
        """bstrings creates an empty -o on a genuine zero-hit scan — a true
        negative must not be reported as a failure."""
        from tools.eztools import ez_bstrings
        mock_dotnet.side_effect = self._writes(0)
        r = ez_bstrings(target, out_dir)
        assert r["success"] is True
        assert r["hits"] == 0
        assert "note" in r

    def test_exit_zero_without_output_is_failure(self, mock_dotnet, target, out_dir):
        """The reported bug: bstrings prints usage, exits 0, writes nothing.
        That must never be surfaced to an analyst as success."""
        from tools.eztools import ez_bstrings
        r = ez_bstrings(target, out_dir)  # run_ok, creates no file
        assert r["success"] is False
        assert "wrote no output" in r["error"]

    def test_stale_output_truncated_not_appended(self, mock_dotnet, target, out_dir):
        """bstrings appends to -o, so a stale file would double the hit count."""
        from tools.eztools import ez_bstrings
        stale = os.path.join(out_dir, "bstrings.txt")
        with open(stale, "w") as fh:
            fh.writelines("old hit\n" for _ in range(100))
        mock_dotnet.side_effect = self._writes(3)
        r = ez_bstrings(target, out_dir)
        assert r["hits"] == 3

    def test_directory_rejected(self, mock_dotnet, tmp_path, out_dir):
        from tools.eztools import ez_bstrings
        r = ez_bstrings(str(tmp_path), out_dir)
        assert r["success"] is False
        assert "directory" in r["error"]
        assert not mock_dotnet.called

    def test_missing_file_rejected(self, mock_dotnet, tmp_path, out_dir):
        from tools.eztools import ez_bstrings
        r = ez_bstrings(str(tmp_path / "nope.bin"), out_dir)
        assert r["success"] is False
        assert "not found" in r["error"]
        assert not mock_dotnet.called


# ── The --csvf family of silent-empty-result bugs ────────────────────────────
#
# WxTCmd, SQLECmd and rla were all passed --csvf, which none of them has. Each
# printed usage, exited 0 and wrote nothing, and Atlas recorded a success. rla was
# additionally mis-modelled: it has no --csv either and emits hives, not CSV.

def _writes(names):
    """run_dotnet mock that creates the files the real tool would write into the
    directory following the given output flag."""
    def side_effect(dll, args, **kwargs):
        flag = "--csv" if "--csv" in args else "--out"
        out = args[args.index(flag) + 1]
        os.makedirs(out, exist_ok=True)
        for n in names:
            with open(os.path.join(out, n), "w") as fh:
                fh.write("Col1,Col2\na,b\n")
        return {"success": True, "stdout": "Results saved to: " + out,
                "stderr": "", "exit_code": 0, "truncated": False, "cmd": "ez"}
    return side_effect


INTEROP_STDOUT = (
    "Error processing database: Unable to load shared library "
    "'SQLite.Interop.dll' or one of its dependencies.\nResults saved to: /out")


@pytest.fixture
def out_dir(tmp_path):
    d = tmp_path / "analysis"
    d.mkdir()
    return str(d)


class TestWxTCmd:
    """WxTCmd has --csv but no --csvf."""

    @pytest.fixture
    def db(self, tmp_path):
        p = tmp_path / "ActivitiesCache.db"
        p.write_bytes(b"SQLite format 3\x00")
        return str(p)

    def test_no_csvf_but_csv_kept(self, mock_dotnet, db, out_dir):
        from tools.eztools import ez_wxtcmd
        mock_dotnet.side_effect = _writes(["20310204_Activity.csv"])
        ez_wxtcmd(db, out_dir)
        args = mock_dotnet.call_args[0][1]
        assert "--csvf" not in args
        assert args[args.index("--csv") + 1] == out_dir

    def test_returns_tool_named_output(self, mock_dotnet, db, out_dir):
        from tools.eztools import ez_wxtcmd
        mock_dotnet.side_effect = _writes(["20310204_Activity.csv",
                                           "20310204_ActivityOperation.csv"])
        r = ez_wxtcmd(db, out_dir)
        assert r["success"] is True
        assert len(r["output_paths"]) == 2

    def test_exit_zero_without_output_is_failure(self, mock_dotnet, db, out_dir):
        from tools.eztools import ez_wxtcmd
        r = ez_wxtcmd(db, out_dir)  # run_ok, writes nothing
        assert r["success"] is False
        assert "wrote no output" in r["error"]

    def test_missing_interop_gets_actionable_hint(self, mock_dotnet, db, out_dir):
        """The real Linux failure: it exits 0 printing 'Results saved to:' after
        failing to load its native library."""
        from tools.eztools import ez_wxtcmd
        mock_dotnet.return_value = {"success": True, "stdout": INTEROP_STDOUT,
                                    "stderr": "", "exit_code": 0,
                                    "truncated": False, "cmd": "ez"}
        r = ez_wxtcmd(db, out_dir)
        assert r["success"] is False
        assert "SQLite.Interop.dll" in r["error"]
        assert "plaso" in r["hint"]

    def test_unrelated_prior_artifact_is_not_credited(self, mock_dotnet, db, out_dir):
        """A CSV another tool already left in analysis/ must not count as output."""
        from tools.eztools import ez_wxtcmd
        with open(os.path.join(out_dir, "mftecmd.csv"), "w") as fh:
            fh.write("x\n")
        r = ez_wxtcmd(db, out_dir)
        assert r["success"] is False

    def test_missing_db_rejected(self, mock_dotnet, tmp_path, out_dir):
        from tools.eztools import ez_wxtcmd
        r = ez_wxtcmd(str(tmp_path / "nope.db"), out_dir)
        assert r["success"] is False
        assert "not found" in r["error"]
        assert not mock_dotnet.called


class TestSqleCmd:
    """SQLECmd has --csv and --maps but no --csvf."""

    @pytest.fixture
    def db(self, tmp_path):
        p = tmp_path / "History"      # Chromium artifacts have no extension
        p.write_bytes(b"SQLite format 3\x00")
        return str(p)

    def test_no_csvf_csv_and_maps_kept(self, mock_dotnet, db, out_dir):
        from tools.eztools import ez_sqlecmd
        mock_dotnet.side_effect = _writes(["ChromiumBrowser_History.csv"])
        ez_sqlecmd(db, out_dir)
        args = mock_dotnet.call_args[0][1]
        assert "--csvf" not in args
        assert args[args.index("--csv") + 1] == out_dir
        assert args[args.index("--maps") + 1].endswith("Maps")

    def test_extensionless_file_uses_f_not_d(self, mock_dotnet, db, out_dir):
        """'History'/'Cookies'/'Web Data' are files; the old endswith('.db')
        test sent every one of them to -d as though it were a directory."""
        from tools.eztools import ez_sqlecmd
        mock_dotnet.side_effect = _writes(["ChromiumBrowser_History.csv"])
        ez_sqlecmd(db, out_dir)
        args = mock_dotnet.call_args[0][1]
        assert "-f" in args and "-d" not in args

    def test_directory_uses_d(self, mock_dotnet, tmp_path, out_dir):
        from tools.eztools import ez_sqlecmd
        src = tmp_path / "profile"
        src.mkdir()
        mock_dotnet.side_effect = _writes(["ChromiumBrowser_History.csv"])
        ez_sqlecmd(str(src), out_dir)
        args = mock_dotnet.call_args[0][1]
        assert "-d" in args and "-f" not in args

    def test_exit_zero_without_output_is_failure(self, mock_dotnet, db, out_dir):
        from tools.eztools import ez_sqlecmd
        r = ez_sqlecmd(db, out_dir)
        assert r["success"] is False
        assert "wrote no output" in r["error"]
        assert "map" in r["hint"]

    def test_runs_in_output_dir_so_byproduct_is_contained(self, mock_dotnet, db, out_dir):
        """SQLECmd extracts a 3.4MB libSQLite.Interop.so into its cwd on every
        run; unset, that lands in whatever directory Atlas was started from."""
        from tools.eztools import ez_sqlecmd
        mock_dotnet.side_effect = _writes(["ChromiumBrowser_History.csv"])
        ez_sqlecmd(db, out_dir)
        assert mock_dotnet.call_args[1]["cwd"] == out_dir

    def test_paths_absolute_when_cwd_is_changed(self, mock_dotnet, tmp_path, out_dir, monkeypatch):
        """A relative db_path would resolve against the changed cwd, so the
        wrapper has to absolutize before handing paths over."""
        from tools.eztools import ez_sqlecmd
        (tmp_path / "History").write_bytes(b"SQLite format 3\x00")
        monkeypatch.chdir(tmp_path)
        mock_dotnet.side_effect = _writes(["ChromiumBrowser_History.csv"])
        ez_sqlecmd("History", out_dir)
        args = mock_dotnet.call_args[0][1]
        assert args[args.index("-f") + 1] == str(tmp_path / "History")
        assert args[args.index("--maps") + 1].startswith("/")

    def test_missing_interop_on_stderr_gets_actionable_hint(self, mock_dotnet, db, out_dir):
        """SQLECmd lets the load failure escape as an unhandled exception on
        stderr, where WxTCmd catches it and prints to stdout — detection has to
        cover both streams."""
        from tools.eztools import ez_sqlecmd
        mock_dotnet.return_value = {
            "success": True, "stdout": "SQLECmd version 1.1.0.0\nMaps loaded: 92",
            "stderr": "Unhandled exception: System.DllNotFoundException: Unable to "
                      "load shared library 'SQLite.Interop.dll'",
            "exit_code": 0, "truncated": False, "cmd": "ez"}
        r = ez_sqlecmd(db, out_dir)
        assert r["success"] is False
        assert "SQLite.Interop.dll" in r["error"]
        assert "plaso" in r["hint"]


class TestRla:
    """rla has NEITHER --csv nor --csvf: it replays transaction logs and writes
    updated HIVES to --out. Do not copy the --csv assertions from the parsers."""

    @pytest.fixture
    def hive_dir(self, tmp_path):
        d = tmp_path / "config"
        d.mkdir()
        (d / "SECURITY").write_bytes(b"regf")
        (d / "SECURITY.LOG1").write_bytes(b"hvle")
        return str(d)

    def test_uses_out_and_never_csv(self, mock_dotnet, hive_dir, out_dir):
        from tools.eztools import ez_rla
        mock_dotnet.side_effect = _writes(["SECURITY"])
        ez_rla(hive_dir, out_dir)
        args = mock_dotnet.call_args[0][1]
        assert "--csv" not in args
        assert "--csvf" not in args
        assert args[args.index("--out") + 1] == out_dir

    def test_directory_uses_d_single_hive_uses_f(self, mock_dotnet, hive_dir, out_dir):
        from tools.eztools import ez_rla
        mock_dotnet.side_effect = _writes(["SECURITY"])
        ez_rla(hive_dir, out_dir)
        assert "-d" in mock_dotnet.call_args[0][1]
        ez_rla(os.path.join(hive_dir, "SECURITY"), out_dir)
        assert "-f" in mock_dotnet.call_args[0][1]

    def test_flatten_names_opt_in_only(self, mock_dotnet, hive_dir, out_dir):
        """Path-encoded names are rla's default because they keep several users'
        NTUSER.DAT from overwriting each other."""
        from tools.eztools import ez_rla
        mock_dotnet.side_effect = _writes(["SECURITY"])
        ez_rla(hive_dir, out_dir)
        assert "--nop" not in mock_dotnet.call_args[0][1]
        ez_rla(hive_dir, out_dir, flatten_names=True)
        assert "--nop" in mock_dotnet.call_args[0][1]

    def test_reports_hives_and_points_at_a_parser(self, mock_dotnet, hive_dir, out_dir):
        from tools.eztools import ez_rla
        def side_effect(dll, args, **kwargs):
            _writes(["SECURITY", "SAM"])(dll, args, **kwargs)
            return {"success": True, "truncated": False, "cmd": "rla",
                    "stderr": "", "exit_code": 0,
                    "stdout": "Hives found: 2\nAt least one transaction log "
                              "was applied. Sequence numbers have been updated"}
        mock_dotnet.side_effect = side_effect
        r = ez_rla(hive_dir, out_dir)
        assert r["success"] is True
        assert r["hives_written"] == 2
        assert r["logs_applied"] == 1
        assert "regripper_hive" in r["hint"]

    def test_no_hives_found_is_explicit_failure(self, mock_dotnet, hive_dir, out_dir):
        from tools.eztools import ez_rla
        mock_dotnet.return_value = {"success": True, "stdout": "Hives found: 0",
                                    "stderr": "", "exit_code": 0,
                                    "truncated": False, "cmd": "rla"}
        r = ez_rla(hive_dir, out_dir)
        assert r["success"] is False
        assert "no registry hives" in r["error"]
        assert ".LOG1" in r["hint"]

    def test_exit_zero_without_output_is_failure(self, mock_dotnet, hive_dir, out_dir):
        from tools.eztools import ez_rla
        r = ez_rla(hive_dir, out_dir)  # run_ok, writes nothing
        assert r["success"] is False
        assert "wrote no output" in r["error"]

    def test_missing_path_rejected(self, mock_dotnet, tmp_path, out_dir):
        from tools.eztools import ez_rla
        r = ez_rla(str(tmp_path / "nope"), out_dir)
        assert r["success"] is False
        assert "not found" in r["error"]
        assert not mock_dotnet.called


class TestMissingTool:
    """An uninstalled tool must name itself, not surface as an opaque dotnet
    error. Whether a given host has a given EZ tool varies, so the resolved
    path here points into tmp_path and the test asserts the code's behaviour,
    not the host's inventory."""

    def test_uninstalled_tool_reports_itself(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_pecmd
        # A real input directory holding a real .pf, so the call gets past the
        # wrapper's own existence check and the missing-tool diagnostic is what
        # is actually being exercised.
        pf = tmp_path / "Prefetch"
        pf.mkdir()
        (pf / "CMD.EXE-1234ABCD.pf").write_bytes(b"SCCA")
        absent = str(tmp_path / "not-provisioned" / "PECmd.dll")
        with patch("tools.eztools._resolve_ez_dll", side_effect=lambda d: absent):
            r = ez_pecmd(str(pf), str(tmp_path / "out"))
        assert r["success"] is False
        assert "PECmd.dll" in r["error"] and "not installed" in r["error"]
        assert "install.sh" in r["hint"]
        assert not mock_dotnet.called


# ── -f / -d dispatch ──────────────────────────────────────────────────────────
#
# Five wrappers picked -f vs -d by pattern-matching the input path's name rather
# than asking the filesystem, so any artifact that was extensionless, renamed, or
# differently-cased was misrouted. That was not merely cosmetic. Handed a file via
# -d, all four installed tools print "does not exist! Exiting" about a path that
# demonstrably does exist and then exit 0: JLECmd/LECmd/RBCmd write no CSV, and
# EvtxECmd writes a header-only one. Atlas recorded that as a success, so an
# analyst asking what was in an artifact got a silent empty result instead.
#
# Each wrapper's old predicate, and a real artifact it misroutes:
#   ez_evtxecmd  endswith(".evtx")            a log exported without its suffix
#   ez_pecmd     endswith(".pf")              AUDIOD~1.PF — uppercase 8.3 names
#                                             really do occur in Prefetch dirs
#   ez_jlecmd    "automaticDestinations" in   correct only by an accident of
#                                             casing: it matched the lowercase
#                                             file suffix while missing the real
#                                             directory "AutomaticDestinations"
#   ez_lecmd     endswith(".lnk")             ".LNK", or a carved shortcut
#   ez_rbcmd     startswith("$I")/"/$I" in    a $I file extracted under a new name

_DISPATCH = [
    ("ez_evtxecmd", "Security.evtx", "Security"),
    ("ez_pecmd", "NOTEPAD.EXE-D8414F97.pf", "AUDIOD~1.PF"),
    ("ez_jlecmd", "f01b4d95cf55d32a.automaticDestinations-ms",
     "f01b4d95cf55d32a.automaticdestinations-ms"),
    ("ez_lecmd", "shortcut.lnk", "SHORTCUT.LNK"),
    ("ez_rbcmd", "$IABCDEF.txt", "deleted_item_01.bin"),
]


@pytest.mark.parametrize("tool,canonical,misrouted", _DISPATCH)
class TestFileOrDirDispatch:
    """-f is for a file and -d for a directory on every one of these tools
    (verified against `dotnet <dll> --help`), and they are mutually exclusive."""

    @staticmethod
    def _call(tool, path, out):
        import tools.eztools as ez
        return getattr(ez, tool)(str(path), str(out))

    @staticmethod
    def _stub_bytes(name: str, tool: str = "") -> bytes:
        # An event log carries the ElfFile signature whatever its name, and
        # the input gate refuses one without it; the stub for an EVTX tool
        # carries it even when the name does not say .evtx.
        if name.casefold().endswith(".evtx") or "evtx" in (tool or "").casefold():
            return b"ElfFile\x00"
        return b"\x00"

    def test_canonically_named_file_uses_f(self, mock_dotnet, tmp_path, out_dir,
                                           tool, canonical, misrouted):
        p = tmp_path / canonical
        p.write_bytes(self._stub_bytes(canonical, tool))
        self._call(tool, p, out_dir)
        args = mock_dotnet.call_args[0][1]
        assert "-f" in args and "-d" not in args

    def test_extensionless_file_uses_f_not_d(self, mock_dotnet, tmp_path, out_dir,
                                             tool, canonical, misrouted):
        """The reported bug: a real artifact whose name the old predicate did not
        recognise was passed to -d as though it were a directory."""
        p = tmp_path / misrouted
        p.write_bytes(self._stub_bytes(misrouted, tool))
        self._call(tool, p, out_dir)
        args = mock_dotnet.call_args[0][1]
        assert "-f" in args and "-d" not in args
        assert args[args.index("-f") + 1] == str(p)

    def test_directory_uses_d(self, mock_dotnet, tmp_path, out_dir,
                              tool, canonical, misrouted):
        d = tmp_path / "artifacts"
        d.mkdir()
        # Non-empty without .evtx is refused for EvtxECmd; seed a stub when needed.
        if tool == "ez_evtxecmd":
            (d / "Security.evtx").write_bytes(b"ElfFile\x00")
        self._call(tool, d, out_dir)
        args = mock_dotnet.call_args[0][1]
        assert "-d" in args and "-f" not in args
        assert args[args.index("-d") + 1] == str(d)

    def test_directory_named_like_a_file_still_uses_d(self, mock_dotnet, tmp_path,
                                                      out_dir, tool, canonical,
                                                      misrouted):
        """The inverse misroute — a directory whose name matches the artifact
        pattern (an extraction tool naming an output dir after the artifact) was
        handed to -f."""
        d = tmp_path / canonical
        d.mkdir()
        if tool == "ez_evtxecmd":
            (d / "Security.evtx").write_bytes(b"ElfFile\x00")
        self._call(tool, d, out_dir)
        args = mock_dotnet.call_args[0][1]
        assert "-d" in args and "-f" not in args

    def test_missing_path_rejected_before_tool_runs(self, mock_dotnet, tmp_path,
                                                    out_dir, tool, canonical,
                                                    misrouted):
        missing = tmp_path / "nope" / canonical
        r = self._call(tool, missing, out_dir)
        assert r["success"] is False
        # Wording varies by gate; assert the substance. See the note in
        # TestEvtxEcmdEmptyResult.test_missing_path_rejected.
        assert str(missing) in r["error"]
        assert not mock_dotnet.called

    def test_broken_symlink_rejected_not_treated_as_file(self, mock_dotnet, tmp_path,
                                                          out_dir, tool, canonical,
                                                          misrouted):
        """Extraction can leave a path that is neither file nor directory. The
        existence check has to come ahead of the isdir test, or a dangling link
        falls through to -f and the tool fails opaquely."""
        link = tmp_path / canonical
        link.symlink_to(tmp_path / "no-such-target")
        r = self._call(tool, link, out_dir)
        assert r["success"] is False
        assert str(link) in r["error"]
        assert not mock_dotnet.called


# ── Boundaries of the empty-result guard ─────────────────────────────────────
#
# Each case here is a way the guard either goes inert (reporting a real parse
# failure as success) or fires when it should not (turning a legitimate
# "no evidence" finding into an error). The second kind is the more damaging in
# a forensic tool, so most of these pin true negatives open.

class TestGuardDoesNotCreditUnrelatedFiles:
    """The guard was inert on most calls. Callers usually pass the case's own
    analysis/ directory as output_dir, and Atlas rewrites trace.json,
    trace.jsonl and evidence_index.db in there *during* the tool call. Those
    landed in the produced set and satisfied the guard, so a run that parsed
    nothing was still reported as a success, with Atlas's own trace log listed as
    the tool's forensic output."""

    def test_trace_log_rewritten_during_the_call_is_not_output(self, mock_dotnet,
                                                              tmp_path, out_dir):
        from tools.eztools import ez_lecmd
        recent = tmp_path / "Recent"
        recent.mkdir()
        (recent / "Bogus.lnk").write_bytes(b"not a shortcut")

        def touches_trace(dll, args, **kwargs):
            # What Atlas itself does to analysis/ while a tool runs.
            for name in ("trace.json", "trace.jsonl", "evidence_index.db"):
                with open(os.path.join(out_dir, name), "w") as fh:
                    fh.write("atlas internal state\n")
            return {"success": True, "stdout": "Found 1 files\nProcessed 0 out of "
                    "1 files in 0.09 seconds", "stderr": "", "exit_code": 0,
                    "truncated": False, "cmd": "ez"}

        mock_dotnet.side_effect = touches_trace
        r = ez_lecmd(str(recent), out_dir)
        assert r["success"] is False, "a non-CSV byproduct must not count as parsed output"
        assert "parsed nothing" in r["error"]
        assert "trace.json" not in str(r.get("output_paths") or [])


class TestGuardHandlesTruncatedStdout:
    """run() keeps only the FIRST 150 lines of stdout, and an EvtxECmd sweep of
    a whole winevt/Logs directory prints far more — so the 'Processed N files'
    summary the guard relies on is gone. Failing on that basis would break the
    canonical absence-proof workflow: sweeping a whole log directory for an
    event ID that is not there."""

    @pytest.fixture
    def logs(self, tmp_path):
        d = tmp_path / "Logs"
        d.mkdir()
        for i in range(5):
            (d / f"Log{i}.evtx").write_bytes(b"ElfFile\x00")
        return str(d)

    def test_per_file_marker_survives_the_cut_and_proves_a_read(self, mock_dotnet,
                                                               logs, out_dir):
        from tools.eztools import ez_evtxecmd
        # The head of a sweep: per-file totals kept, summary cut off.
        mock_dotnet.return_value = {
            "success": True, "truncated": True, "exit_code": 0, "stderr": "",
            "cmd": "ez", "stdout": "Total event log records found: 20\n"
                                   "Records included: 0 Errors: 0 Events dropped: 20"}
        r = ez_evtxecmd(logs, out_dir, event_ids="31337")
        assert r["success"] is True, "a truncated summary must not read as a failure"
        assert "records in scope" in r["note"]

    def test_truncated_without_a_marker_is_unverified_not_empty(self, mock_dotnet,
                                                               logs, out_dir):
        """Nothing proved the logs were read, but nothing proved they were not.
        Reporting an absence here would be the overclaim; say it is unverified."""
        from tools.eztools import ez_evtxecmd
        mock_dotnet.return_value = {"success": True, "truncated": True,
                                    "exit_code": 0, "stderr": "", "cmd": "ez",
                                    "stdout": "Processing Log0.evtx..."}
        r = ez_evtxecmd(logs, out_dir)
        assert r["success"] is True
        assert "could not be confirmed" in r["note"]
        assert "5 .evtx log(s)" in r["note"]


class TestProcessedBeatsTheFilenameTest:
    """If the tool says it read a file, it read one, whatever the file is called.
    Checking the artifact-name test first declared a carved log with no extension
    'not a .evtx log' while EvtxECmd's own output said it had parsed it — and a
    carved, renamed or extensionless artifact is exactly the input class the
    wrapper's dispatch fix exists to serve."""

    def test_extensionless_carved_log_read_by_the_tool_is_a_true_negative(
            self, mock_dotnet, tmp_path, out_dir):
        from tools.eztools import ez_evtxecmd
        carved = tmp_path / "00001234.bin"          # no .evtx suffix
        carved.write_bytes(b"ElfFile\x00")
        mock_dotnet.side_effect = _writes_header_only(
            ["evtx.csv"], "Total event log records found: 0\n"
                          "Processed 1 file in 1.39 seconds")
        r = ez_evtxecmd(str(carved), out_dir)
        assert r["success"] is True, "the tool reported reading it; not a wrong input"
        assert "records in scope" in r["note"]

    def test_a_file_the_tool_never_read_is_still_a_wrong_input(self, mock_dotnet,
                                                              tmp_path, out_dir):
        """The counterpart that must keep failing: an NTFS $I30 index attribute
        handed to RBCmd, which writes a header-only CSV and exits 0."""
        from tools.eztools import ez_rbcmd
        i30 = tmp_path / "$I30"
        i30.write_bytes(b"INDX")
        mock_dotnet.side_effect = _writes_header_only(
            ["recyclebin.csv"], "Found 1 files. Processing...\n"
                                "Processed 0 out of 1 files in 0.008 seconds")
        r = ez_rbcmd(str(i30), out_dir)
        assert r["success"] is False
        assert "is not a $I Recycle Bin record" in r["error"]


class TestCandidateCountFollowsSymlinks:
    """The tools follow symlinked directories; os.walk does not by default. A
    zero candidate count under a symlinked subtree the tool actually read turned
    a real parse failure into 'a true negative, not a failure' — the dangerous
    direction. misc.symlink_evidence exists to hand tools symlinked paths."""

    def test_unparseable_artifact_behind_a_symlink_still_fails(self, mock_dotnet,
                                                              tmp_path, out_dir):
        from tools.eztools import ez_lecmd
        real = tmp_path / "real"
        real.mkdir()
        (real / "Bogus.lnk").write_bytes(b"not a shortcut")
        base = tmp_path / "base"
        base.mkdir()
        (base / "sub").symlink_to(real, target_is_directory=True)
        mock_dotnet.side_effect = _writes_nothing(
            "Found 1 files\nProcessed 0 out of 1 files in 0.09 seconds")
        r = ez_lecmd(str(base), out_dir)
        assert r["success"] is False, "the .lnk behind the symlink must be counted"
        assert "1 .lnk shortcut(s) are present" in r["error"]

    def test_symlink_cycle_does_not_hang(self, mock_dotnet, tmp_path, out_dir):
        from tools.eztools import ez_lecmd
        base = tmp_path / "base"
        base.mkdir()
        (base / "loop").symlink_to(base, target_is_directory=True)
        mock_dotnet.side_effect = _writes_nothing("Found 0 files")
        r = ez_lecmd(str(base), out_dir)
        assert r["success"] is True
        assert "nothing to" in r["note"]


class TestPartialParseIsFlagged:
    def test_failed_files_section_notes_partial_coverage(self, mock_dotnet,
                                                        tmp_path, out_dir):
        """A sweep where some artifacts parsed and others did not still returns
        rows, so it short-circuited to a clean success and the analyst never
        learned the coverage was incomplete."""
        from tools.eztools import ez_lecmd
        recent = tmp_path / "Recent"
        recent.mkdir()
        (recent / "good.lnk").write_bytes(b"L\x00\x00\x00")
        (recent / "bad.lnk").write_bytes(b"junk")
        mock_dotnet.side_effect = _writes_rows(
            ["lnk.csv"], rows=1,
            extra_stdout="Failed files\n  bad.lnk ==> (invalid signature!)")
        r = ez_lecmd(str(recent), out_dir)
        assert r["success"] is True
        assert "only the files that parsed" in r["note"]


class TestOutputDirErrorsAreReturnedNotRaised:
    def test_output_dir_that_is_a_file_returns_an_error(self, mock_dotnet,
                                                       tmp_path):
        """os.makedirs raises FileExistsError when output_dir names an existing
        file; that escaped the wrapper as a traceback instead of a tool result."""
        from tools.eztools import ez_evtxecmd
        logs = tmp_path / "Logs"
        logs.mkdir()
        (logs / "Security.evtx").write_bytes(b"ElfFile\x00")
        clash = tmp_path / "out.csv"
        clash.write_text("i am a file\n")
        r = ez_evtxecmd(str(logs), str(clash))
        assert r["success"] is False
        assert "output_dir" in r["error"]
        assert not mock_dotnet.called


class TestEvtxTimeWindow:
    def test_bounds_take_evtxecmd_form(self):
        from tools.eztools import _evtx_time_bound as b
        assert b("2031-02-04") == "2031-02-04 00:00:00.0000000"
        assert b("2031-02-04", end=True) == "2031-02-04 23:59:59.9999990"
        assert b("2031-02-04T14:00:00Z") == "2031-02-04 14:00:00.0000000"
        assert b("2031-02-04 14:00") == "2031-02-04 14:00:00.0000000"
        assert b("2031-02-04T16:00:00+02:00") == "2031-02-04 14:00:00.0000000"
        assert b("") is None and b(None) is None
        with pytest.raises(ValueError):
            b("yesterday")

    def test_event_ids_take_inc_form(self):
        from tools.eztools import _normalize_event_ids as n
        assert n("(4624, 4625)") == "4624,4625"
        assert n("[4625,4624]") == "4624,4625"
        assert n([4624, "4625"]) == "4624,4625"
        assert n("5500-5600,4624") == "4624,5500-5600"
        assert n("") is None and n(None) is None

    def test_window_and_ids_reach_evtxecmd(self, tmp_path):
        from unittest.mock import patch
        from tests.conftest import make_evtx
        from tools import eztools
        log = make_evtx(tmp_path / "winevt" / "Security.evtx")
        seen = {}

        def fake_ez(dll, args, output_dir=None, timeout=0):
            seen["args"] = args
            return {"success": True, "stdout": "", "stderr": "", "exit_code": 0}
        with patch.object(eztools, "_ez", fake_ez), \
             patch.object(eztools, "_guard_parsed_output", lambda result, *a, **k: result), \
             patch.object(eztools, "_attach_evtx_coverage", lambda *a, **k: None):
            r = eztools.ez_evtxecmd(str(log), str(tmp_path / "out"), event_ids="(4624, 4625)",
                                    time_start="2031-02-04T14:00:00Z", time_end="2031-02-04")
        assert r["success"] is True
        a = seen["args"]
        assert a[a.index("--inc") + 1] == "4624,4625"
        assert a[a.index("--sd") + 1] == "2031-02-04 14:00:00.0000000"
        assert a[a.index("--ed") + 1] == "2031-02-04 23:59:59.9999990"
        assert r["time_window_utc"]["start"] == "2031-02-04 14:00:00.0000000"
        bad = eztools.ez_evtxecmd(str(log), str(tmp_path / "out"), time_start="last tuesday")
        assert bad["success"] is False and bad["gate"] == "bad_args"
        late = eztools.ez_evtxecmd(str(log), str(tmp_path / "out"),
                                   time_start="2031-02-05", time_end="2031-02-04")
        assert late["gate"] == "bad_args"

    def test_memo_is_keyed_on_the_window_too(self, tmp_path):
        from tools.eztools import _evtx_parse_memo_lookup as look, _evtx_parse_memo_record as rec
        out = tmp_path / "out"; out.mkdir()
        (out / "w.csv").write_text("h\n1\n")
        log = str(tmp_path / "Security.evtx")
        rec(str(out), log, "4624", "w.csv", ("2031-02-04 00:00:00.0000000", "2031-02-04 23:59:59.9999990"))
        assert look(str(out), log, "4624", ("2031-02-04 00:00:00.0000000", "2031-02-04 23:59:59.9999990"))
        assert look(str(out), log, "4624") is None            # wider request: not covered
        assert look(str(out), log, "4624", ("2031-02-03 00:00:00.0000000", None)) is None
        (out / "all.csv").write_text("h\n1\n")
        rec(str(out), log, None, "all.csv")                    # full parse covers everything
        assert look(str(out), log, "4625", ("2031-02-01 00:00:00.0000000", None))["gate"] == "parse_memo"


class TestOutputDirDefaultsToTheCase:
    """Every parser writes CSVs somewhere the caller names; a call that names
    nothing gets analysis/exports under the open case, and only outside a
    case is the directory required."""

    def test_an_omitted_output_dir_lands_under_the_open_case(self, tmp_path, mock_dotnet):
        from unittest.mock import MagicMock
        from tools.eztools import ez_pecmd
        pf = tmp_path / "evidence" / "X.pf"
        pf.parent.mkdir(parents=True)
        pf.write_bytes(b"MAM\x04")
        elog = MagicMock()
        elog.case_dir.return_value = str(tmp_path)
        with patch("core.execution_log.log", elog):
            getattr(ez_pecmd, "fn", ez_pecmd)(str(pf))
        args = mock_dotnet.call_args[0][1]
        assert args[args.index("--csv") + 1] == str(tmp_path / "analysis" / "exports")
        assert (tmp_path / "analysis" / "exports").is_dir()

    def test_outside_a_case_the_directory_is_required(self, tmp_path, mock_dotnet):
        from unittest.mock import MagicMock
        from tools.eztools import ez_amcacheparser
        elog = MagicMock()
        elog.case_dir.return_value = None
        with patch("core.execution_log.log", elog):
            out = getattr(ez_amcacheparser, "fn", ez_amcacheparser)(str(tmp_path / "Amcache.hve"))
        assert out["success"] is False and "output_dir is required" in out["error"]
        mock_dotnet.assert_not_called()
