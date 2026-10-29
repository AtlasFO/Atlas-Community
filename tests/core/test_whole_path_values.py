"""A path parameter's value and the evidence reference are one path, spaces
and all, whether or not the path exists now (core.provenance.path_tokens,
core.middleware._extract_evidence_ref, core.paths.is_path_param). Invented
fixtures only (CORP-WS01, jane.doe)."""
from __future__ import annotations

import json

from core import provenance
from core.middleware import _extract_evidence_ref
from core.paths import is_path_param

SPACED = "mnt/corp-ws01/fs/Documents and Settings/jane.doe/NTUSER.DAT"


def test_a_path_parameter_with_a_space_is_one_token_though_it_does_not_exist(tmp_path):
    entry = {"cmd": f"rip.pl -r {tmp_path}/{SPACED} -p userassist",
             "args": json.dumps({"hive_path": SPACED, "plugin": "userassist"})}
    toks = provenance.path_tokens(entry, tmp_path)
    assert SPACED in toks
    assert not any(t.rstrip("/").endswith("/fs/Documents") for t in toks)


def test_a_folder_named_like_the_cut_fragment_is_not_read(tmp_path):
    """A real folder "Documents" beside the spaced path: the fragment the
    tokenizer cuts must not stand for it."""
    (tmp_path / "mnt/corp-ws01/fs/Documents").mkdir(parents=True)
    entry = {"cmd": f"rip.pl -r {tmp_path}/{SPACED} -p userassist", "args": json.dumps({"hive_path": SPACED})}
    toks = provenance.path_tokens(entry, tmp_path)
    assert not any(t.rstrip("/").endswith("fs/Documents") for t in toks)


def test_a_non_path_argument_with_slashes_and_spaces_is_not_made_a_path(tmp_path):
    entry = {"cmd": "<py>:strings_strings_grep",
             "args": json.dumps({"pattern": "foo / bar baz/qux quux", "path": "analysis/out.txt"})}
    toks = provenance.path_tokens(entry, tmp_path)
    assert "foo / bar baz/qux quux" not in toks


def test_a_logged_command_without_arguments_names_its_input_by_the_whole_reference(tmp_path):
    entry = {"cmd": f"grep -n Mr {SPACED}", "evidence_ref": SPACED}
    toks = provenance.path_tokens(entry, tmp_path)
    assert SPACED in toks and not any(t.rstrip("/").endswith("/fs/Documents") for t in toks)


def test_the_evidence_reference_of_a_path_parameter_is_its_whole_value():
    assert _extract_evidence_ref({"hive_path": SPACED}) == SPACED
    long = "mnt/corp-ws01/fs/" + "/".join(["a long folder name"] * 20) + "/x.log"
    assert _extract_evidence_ref({"file_path": long}) == long
    # another argument keeps the cut match
    assert _extract_evidence_ref({"note": SPACED}) == "mnt/corp-ws01/fs/Documents"


def test_path_parameters_are_named_in_one_place():
    from agent.toolbox import _path_param
    for name in ("hive_path", "mft_path", "recycle_bin_path", "pcap_file", "file_path", "image", "dir_path"):
        assert is_path_param(name) and _path_param(name)
    for name in ("pattern", "plugin", "max_lines", "output_format"):
        assert not is_path_param(name) and not _path_param(name)


def test_the_trace_keeps_a_long_evidence_reference_whole(tmp_path):
    import core.execution_log as elog
    long = "mnt/corp-ws01/fs/" + "/".join(["a long folder name"] * 20) + "/x.log"
    (tmp_path / "analysis").mkdir()
    elog.log.configure("CASE-A", str(tmp_path / "analysis" / "CASE-A_trace.json"), save_session=False)
    elog.log.record_tool_call("<py>:files_read_text", True, False, 0, 0, evidence_ref=long)
    assert elog.log._entries[-1]["evidence_ref"] == long
