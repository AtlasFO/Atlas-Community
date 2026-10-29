"""``output_file`` is a file name inside the call's output_dir (the EZ
parsers' --csvf), never a case path of its own: the middleware leaves it as
given, the written path is output_dir/<name> for every reader of output
parameters, and a name that climbs out of the case is still refused.
Invented case and host names only."""
from __future__ import annotations

import ast
import pathlib

import pytest

import core.execution_log as elog


@pytest.fixture
def case(tmp_path):
    (tmp_path / "analysis").mkdir()
    elog.log.configure("CASE-A", str(tmp_path / "analysis" / "CASE-A_trace.json"), save_session=False)
    return tmp_path


def test_the_middleware_resolves_the_folder_and_leaves_the_name(case):
    from core.middleware import _resolve_case_paths
    out = _resolve_case_paths("ez_ez_evtxecmd", {"output_dir": "analysis/evtx_csv", "output_file": "CORP-WS01.csv"})
    assert out["output_dir"] == str(case / "analysis" / "evtx_csv")
    assert out["output_file"] == "CORP-WS01.csv"


def test_every_reader_of_output_parameters_joins_the_name_under_the_folder(case):
    from core.paths import output_paths
    from core.provenance import _output_params
    args = {"output_dir": str(case / "analysis" / "evtx_csv"), "output_file": "CORP-WS01.csv"}
    written = str(case / "analysis" / "evtx_csv" / "CORP-WS01.csv")
    assert written in output_paths(args)
    import json
    assert written in _output_params({"args": json.dumps(args)})


def test_a_name_that_leaves_the_case_is_refused(case):
    from core.paths import output_safe

    @output_safe
    def parse(evtx_path: str, output_dir: str, output_file: str = "evtx.csv") -> dict:
        return {"success": True}
    assert parse("x", str(case / "analysis"), output_file="CORP-WS01.csv")["success"]
    with pytest.raises(ValueError):
        parse("x", str(case / "analysis"), output_file="/etc/atlas-outside.csv")


def test_every_output_file_parameter_is_a_name_under_output_dir():
    """Each tool function that takes output_file also takes output_dir and
    joins the name under it: the parameter class holds for all of them."""
    root = pathlib.Path(__file__).resolve().parents[2] / "tools"
    seen = 0
    for path in root.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names = [a.arg for a in node.args.args + node.args.kwonlyargs]
                if "output_file" in names:
                    seen += 1
                    assert "output_dir" in names, f"{path.name}:{node.name}"
    assert seen


def test_an_identical_evtx_parse_after_one_is_sent_to_its_csv(case, monkeypatch):
    """The parse memo records the CSV the parser wrote (output_dir/<name>):
    an identical request after it is answered with that CSV, no re-parse.
    The parser is mocked; it writes its CSV under --csv by --csvf's name."""
    import os
    from core.middleware import _resolve_case_paths
    from tools import eztools
    logs = case / "evidence" / "Logs"
    logs.mkdir(parents=True)
    (logs / "Security.evtx").write_bytes(b"ElfFile\x00")

    def parser(_dll, argv, **_kw):
        out = os.path.join(argv[argv.index("--csv") + 1], os.path.basename(argv[argv.index("--csvf") + 1]))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("TimeCreated,EventId\n2031-03-04 09:12:00,4624\n")
        return {"success": True, "stdout": "Processed 1 file", "cmd": "dotnet EvtxECmd.dll"}
    monkeypatch.setattr(eztools, "_ez", parser)
    args = {"evtx_path": str(logs), "output_dir": "analysis/evtx_csv", "output_file": "CORP-WS01.csv",
            "event_ids": "4624"}
    args = _resolve_case_paths("ez_ez_evtxecmd", args) or args
    eztools.ez_evtxecmd(**args)
    again = eztools.ez_evtxecmd(**args)
    assert again.get("gate") == "parse_memo"
    assert again["existing_csv"] == str(case / "analysis" / "evtx_csv" / "CORP-WS01.csv")
