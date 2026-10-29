"""ATLAS_REPORT_INPUTS_AT_RENDER: every writer path assembles its report
through core.report_assemble.assemble_client_report, so the indicator files
the Indicators section points at (and the next steps) are prepared there,
never left to the caller. Invented fixtures only (CORP-WS01, 203.0.113.x,
dates in 2031)."""
from __future__ import annotations

from core.claim_graph import add_claim, set_claim_indicators
from core.report_assemble import assemble_client_report


def _case(tmp_path):
    case = tmp_path / "C"
    for d in (".atlas", "evidence", "analysis", "reports"):
        (case / d).mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** CASE-A\n")
    cid = add_claim(case, "CORP-WS01 connected to 203.0.113.7 at 2031-02-04 12:30:00 UTC.",
                    confidence="LIKELY", host="CORP-WS01", enforce_validation=False)["node_id"]
    set_claim_indicators(case, cid, [{"type": "ip", "value": "203.0.113.7", "side": "attacker"}])
    return case


def test_a_report_assembled_without_a_writer_preparing_it_has_its_indicator_files(tmp_path):
    case = _case(tmp_path)
    md = assemble_client_report(case, report_scope="estate")
    assert (case / "reports" / "CASE-A_iocs.md").is_file() and (case / "reports" / "CASE-A_iocs.csv").is_file()
    assert "reports/CASE-A_iocs.md" in md and "could not be written" not in md


def test_off_the_assembler_leaves_the_files_to_the_writer_path(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_REPORT_INPUTS_AT_RENDER", "0")
    case = _case(tmp_path)
    md = assemble_client_report(case, report_scope="estate")
    assert not (case / "reports" / "CASE-A_iocs.md").exists() and "could not be written" in md


def test_a_call_cited_twice_is_one_sighting(monkeypatch):
    from core import indicators as I
    entry = {"type": "tool_call"}
    monkeypatch.setattr(I, "_evidence_entries", lambda ids: [(c, entry) for c in ids])
    monkeypatch.setattr(I, "_sighting", lambda kind, value, cid, e, **kw: {"call": cid, "host": "CORP-WS01"})
    monkeypatch.setattr(I, "_evidence_calls", lambda by: [])
    assert [s["call"] for s in I.sightings("ip", "203.0.113.7", [41, 41, 42])] == [41, 42]


def test_a_repeat_render_over_an_unchanged_graph_prepares_nothing(tmp_path, monkeypatch):
    from core import ioc_catalog, report_projection as P
    case = _case(tmp_path)
    calls = []
    real = ioc_catalog.write_indicator_files
    monkeypatch.setattr(ioc_catalog, "write_indicator_files", lambda c: calls.append(1) or real(c))
    assemble_client_report(case, report_scope="estate")
    assemble_client_report(case, report_scope="estate")
    assert len(calls) == 1
    add_claim(case, "CORP-WS01 connected to 203.0.113.8 at 2031-02-04 12:40:00 UTC.",
              confidence="LIKELY", host="CORP-WS01", enforce_validation=False)
    assemble_client_report(case, report_scope="estate")
    assert len(calls) == 2
    (case / "reports" / "CASE-A_iocs.md").unlink()       # files gone: written again
    assemble_client_report(case, report_scope="estate")
    assert len(calls) == 3 and (case / "reports" / "CASE-A_iocs.md").is_file()
    P._PREPARED.clear()
