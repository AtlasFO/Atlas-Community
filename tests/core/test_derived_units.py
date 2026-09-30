"""A directory a tool filled becomes a ledger unit that says what it
holds, a look at any file inside probes it, a rebuild keeps it, and the
exit blocker names its contents."""
import json

from core import coverage_ledger as cl


def _case(tmp_path):
    case = tmp_path / "CASE"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence").mkdir()
    carved = case / "analysis" / "carved"
    carved.mkdir(parents=True)
    for name in ("00001.jpg", "00002.jpg", "00003.gif"):
        (carved / name).write_bytes(b"x")
    (case / "exports" / "empty").mkdir(parents=True)
    return case


def _register(case, **kw):
    args = {"image_path": "evidence/usb.dd", "output_dir": "analysis/carved"}
    args.update(kw.pop("arguments", {}))
    return cl.register_derived_outputs(
        str(case), tool_name=kw.pop("tool_name", "carve_foremost"), arguments=args,
        result_text=kw.pop("result_text", json.dumps({"success": True, "output_dir": "analysis/carved"})))


def test_a_filled_output_directory_becomes_a_unit_that_says_what_it_holds(tmp_path):
    case = _case(tmp_path)
    assert _register(case) == ["analysis/carved"]
    unit = next(iter(cl.load_ledger(case)["units"].values()))
    assert unit["kind"] == "derived" and unit["status"] == "unseen"
    assert unit["reason"] == "produced by carve_foremost from usb.dd; 3 files: 2 jpg, 1 gif"
    assert _register(case) == []  # already known
    assert cl._gap_label(unit).startswith("analysis/carved (produced by carve_foremost")


def test_empty_failed_and_evidence_directories_are_not_units(tmp_path):
    case = _case(tmp_path)
    assert _register(case, arguments={"output_dir": "exports/empty"},
                     result_text='{"success": true}') == []
    assert _register(case, result_text='TOOL ERROR {"success": false}') == []
    assert _register(case, arguments={"output_dir": "evidence"},
                     result_text='{"success": true}') == []
    assert cl.load_ledger(case)["units"] == {}


def test_a_look_at_one_carved_file_probes_the_directory(tmp_path):
    case = _case(tmp_path)
    _register(case)
    cl.mark_paths(case, ["analysis/carved/00002.jpg"])
    unit = next(iter(cl.load_ledger(case)["units"].values()))
    assert unit["status"] == "probed"


def test_a_rebuild_keeps_the_derived_unit(tmp_path):
    case = _case(tmp_path)
    _register(case)
    rebuilt = cl.build_coverage_ledger(case)
    assert [u["kind"] for u in rebuilt["units"].values()] == ["derived"]
