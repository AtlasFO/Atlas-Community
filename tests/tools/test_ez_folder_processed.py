"""A folder parse of LECmd, JLECmd or RBCmd is stamped with the files its own
report names (tools.eztools.folder_processed), only files of its input, and
the stamp is read credit (core.evidence_identity.call_reads processed).
Invented fixtures only (jane.doe, 2031)."""
from __future__ import annotations

from tools.eztools import EZ_PROCESSED_LINE, EZ_SOURCE_LINE, _stamp_folder_processed, folder_processed
from tests.core.test_contents_index import case  # noqa: F401,E402


def _recent(tmp_path):
    d = tmp_path / "Users/jane.doe/AppData/Roaming/Microsoft/Windows/Recent"
    d.mkdir(parents=True)
    for name in ("report (final).docx.lnk", "notes.txt.lnk"):
        (d / name).write_bytes(b"L\0\0\0")
    return d


def test_the_processed_lines_name_the_folders_files(tmp_path):
    d = _recent(tmp_path)
    out = "\n".join([f"Processing {d}/report (final).docx.lnk",
                     f"---------- Processed {d}/report (final).docx.lnk in 0.16113480 seconds ----------",
                     f"---------- Processed {d}/notes.txt.lnk in 0.00461890 seconds ----------",
                     f"---------- Processed {d}/notes.txt.lnk in 0.00461890 seconds ----------"])
    assert folder_processed(out, str(d), EZ_PROCESSED_LINE) == [str(d / "report (final).docx.lnk"),
                                                                 str(d / "notes.txt.lnk")]


def test_a_forged_line_outside_the_input_or_of_no_file_names_nothing(tmp_path):
    d = _recent(tmp_path)
    (tmp_path / "secret.txt").write_text("x")
    out = "\n".join([f"Source file: {tmp_path}/secret.txt",
                     f"Source file: {d}/../../../../../../../secret.txt",
                     f"Source file: {d}/missing.lnk",
                     f"Source file: {d}/notes.txt.lnk"])
    assert folder_processed(out, str(d), EZ_SOURCE_LINE) == [str(d / "notes.txt.lnk")]


def test_a_single_file_input_names_itself_only(tmp_path):
    d = _recent(tmp_path)
    f = d / "notes.txt.lnk"
    out = f"Source file: {f}\nSource file: {d}/report (final).docx.lnk"
    assert folder_processed(out, str(f), EZ_SOURCE_LINE) == [str(f)]


def test_the_stamp_is_on_the_calls_own_entry(tmp_path, monkeypatch):
    import core.execution_log as elog
    d = _recent(tmp_path)
    (tmp_path / "analysis").mkdir()
    elog.log.configure("CASE-A", str(tmp_path / "analysis" / "CASE-A_trace.json"), save_session=False)
    monkeypatch.setattr(elog.log, "case_dir", lambda: str(tmp_path))
    cid = elog.log.record_tool_call("dotnet LECmd.dll -d x", True, False, 0, 0)
    _stamp_folder_processed({"_atlas_call_id": cid, "success": True,
                             "stdout": f"---------- Processed {d}/notes.txt.lnk in 0.1 seconds ----------"},
                            str(d), EZ_PROCESSED_LINE)
    entry = next(e for e in elog.log._entries if e.get("call_id") == cid)
    assert [f["path"] for f in entry["processed"]["files"]] == [
        "Users/jane.doe/AppData/Roaming/Microsoft/Windows/Recent/notes.txt.lnk"]
    # a failed run stamps nothing
    cid2 = elog.log.record_tool_call("dotnet LECmd.dll -d x", False, False, 1, 0)
    _stamp_folder_processed({"_atlas_call_id": cid2, "success": False,
                             "stdout": f"---------- Processed {d}/notes.txt.lnk in 0.1 seconds ----------"},
                            str(d), EZ_PROCESSED_LINE)
    assert "processed" not in next(e for e in elog.log._entries if e.get("call_id") == cid2)


def test_the_three_folder_wrappers_stamp_their_report(tmp_path, monkeypatch):
    import core.execution_log as elog
    import tools.eztools as E
    d = _recent(tmp_path)
    (tmp_path / "analysis").mkdir()
    elog.log.configure("CASE-A", str(tmp_path / "analysis" / "CASE-A_trace.json"), save_session=False)
    monkeypatch.setattr(elog.log, "case_dir", lambda: str(tmp_path))
    monkeypatch.setattr(E, "assert_output_safe", lambda *a, **k: None)
    reports = {"LECmd": f"---------- Processed {d}/notes.txt.lnk in 0.1 seconds ----------",
               "JLECmd": f"---------- Processed {d}/notes.txt.lnk in 0.1 seconds ----------",
               "RBCmd": f"Source file: {d}/notes.txt.lnk"}

    def fake_ez(dll, args, output_dir=None, **kw):
        tool = dll.rsplit("/", 1)[-1].removesuffix(".dll")
        cid = elog.log.record_tool_call(f"dotnet {tool}.dll", True, False, 0, 0)
        return {"success": True, "_atlas_call_id": cid, "stdout": reports[tool]}
    monkeypatch.setattr(E, "_ez", fake_ez)
    for fn in (E.ez_lecmd, E.ez_jlecmd, E.ez_rbcmd):
        fn(str(d), output_dir=str(tmp_path / "analysis"))
    stamped = [e for e in elog.log._entries if e.get("processed")]
    assert len(stamped) == 3


def test_a_class_parsed_into_no_output_file_says_so(case, monkeypatch):
    from core import contents_index as ci
    from core.coverage_ledger import load_ledger
    from core.evidence_disposition import credit_dispositions, report_lines
    from tests.core.test_evidence_disposition import _built
    led = _built(case, monkeypatch)
    image = next(i for i in led["items"].values() if i["kind"] == "image")
    label = next(c["label"] for c in led["classes"].values() if c["item"] == image["id"])
    monkeypatch.setattr(ci, "read_state_by_class", lambda c, imgs, files=None: {img: {
        label: {"total": 2, "read": 0, "partial": 0, "parsed": 2, "outputs": [], "filters": []}} for img in imgs})
    credit_dispositions(case)
    c = next(c for c in load_ledger(case)["classes"].values() if c["item"] == image["id"] and c["label"] == label)
    assert c["state"] == "parsed" and "into ," not in c["reason"]
    assert c["reason"].startswith("2 of 2 files parsed into no output file: parse them into an output or read them")
    lines = report_lines(case)
    assert any(f": {label} (" in ln and "into no output file" in ln for ln in lines)
    assert not any(ln.startswith("- ?:") for ln in lines)
