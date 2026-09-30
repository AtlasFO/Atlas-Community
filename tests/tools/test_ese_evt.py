"""ESE databases and legacy .evt logs are recognised by their headers, an
.evtx is redirected to its own parsers, exports are listed table by table
or record by record, and a missing exporter is named."""
import os
from unittest.mock import patch

from core.input_kind import refuse_non_ese, refuse_non_evt
from tools import ese, evt

ESE = b"\x00\x00\x00\x00\xef\xcd\xab\x89" + b"\x00" * 24
EVT = b"\x30\x00\x00\x00LfLe" + b"\x00" * 24
EVTX = b"ElfFile\x00" + b"\x00" * 24


def test_headers_decide_what_a_file_is(tmp_path):
    db = tmp_path / "SRUDB.dat"
    db.write_bytes(ESE)
    assert refuse_non_ese(str(db)) is None
    assert refuse_non_ese(str(tmp_path)) is None  # a directory passes to the caller
    log = tmp_path / "SecEvent.Evt"
    log.write_bytes(EVT)
    assert refuse_non_evt(str(log)) is None
    csv = tmp_path / "parsed.csv"
    csv.write_bytes(b"a,b\n1,2\n")
    assert "not an ESE database" in refuse_non_ese(str(csv))["error"]
    assert "not a legacy .evt" in refuse_non_evt(str(csv))["error"]
    new = tmp_path / "Security.evtx"
    new.write_bytes(EVTX)
    assert "ez.evtxecmd" in refuse_non_evt(str(new))["error"]
    assert "does not exist" in refuse_non_ese(str(tmp_path / "missing.dat"))["error"]


def test_esedb_export_lists_the_tables_it_wrote(tmp_path):
    db = tmp_path / "WebCacheV01.dat"
    db.write_bytes(ESE)
    out = tmp_path / "out"
    seen = {}

    def fake_run(argv, **kw):
        seen["argv"] = argv
        export = argv[argv.index("-t") + 1] + ".export"
        os.makedirs(export)
        with open(os.path.join(export, "Containers"), "w") as f:
            f.write("id\tname\n1\tHistory\n2\tCookies\n")
        with open(os.path.join(export, "MSysObjects"), "w") as f:
            f.write("id\n")
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}

    with patch.object(ese, "tool_program", lambda n: "/usr/bin/esedbexport"), \
            patch.object(ese, "run", fake_run):
        result = ese.esedb_export(str(db), str(out), table="Containers", mode="all")
    assert result["success"] and result["table_count"] == 2
    assert result["tables"][0] == {"table": "Containers", "rows": 2,
                                   "bytes": os.path.getsize(out / "WebCacheV01.dat.export" / "Containers")}
    assert result["tables"][1]["rows"] == 0
    assert seen["argv"][1:5] == ["-m", "all", "-T", "Containers"]
    assert result["artifact_paths"][0].endswith("WebCacheV01.dat.export/Containers")


def test_esedb_export_without_tables_is_a_failure_with_a_next_step(tmp_path):
    db = tmp_path / "SRUDB.dat"
    db.write_bytes(ESE)
    with patch.object(ese, "tool_program", lambda n: "/usr/bin/esedbexport"), \
            patch.object(ese, "run", lambda argv, **kw: {"success": False, "exit_code": 1,
                                                         "stdout": "", "stderr": "unable to open"}):
        result = ese.esedb_export(str(db), str(tmp_path / "out"))
    assert result["success"] is False and "unable to open" in result["error"]
    assert "esedb_info" in result["next_step"]
    with patch.object(ese, "tool_program", lambda n: None):
        assert ese.esedb_export(str(db), str(tmp_path / "out"))["gate"] == "program_missing"
        assert ese.esedb_info(str(db))["gate"] == "program_missing"


def test_evt_export_writes_the_records_to_a_file(tmp_path):
    log = tmp_path / "AppEvent.Evt"
    log.write_bytes(EVT)
    text = ("Event number\t\t: 1\nSource name\t\t: Service Control Manager\n\n"
            "Event number\t\t: 2\nSource name\t\t: Userenv\n")
    seen = {}

    def fake_run(argv, **kw):
        seen["argv"] = argv
        return {"success": True, "exit_code": 0, "stdout": text, "stderr": ""}

    with patch.object(evt, "tool_program", lambda n: "/usr/bin/evtexport"), \
            patch.object(evt, "run", fake_run):
        result = evt.evt_export(str(log), str(tmp_path / "out"), mode="all",
                                resources_dir=str(tmp_path))
    assert result["success"] and result["records"] == 2
    assert open(result["output_path"]).read() == text
    assert result["artifact_paths"] == [result["output_path"]]
    assert seen["argv"][1:5] == ["-m", "all", "-p", str(tmp_path)]
    with patch.object(evt, "tool_program", lambda n: "/usr/bin/evtexport"), \
            patch.object(evt, "run", lambda argv, **kw: {"success": True, "exit_code": 0,
                                                         "stdout": "", "stderr": ""}):
        empty = evt.evt_export(str(log), str(tmp_path / "out"))
    assert empty["success"] is False and "no records" in empty["error"]
    with patch.object(evt, "tool_program", lambda n: None):
        assert evt.evt_export(str(log), str(tmp_path / "out"))["gate"] == "program_missing"
