"""ATLAS_PROFILE_INSIDE_IMAGES: a class whose files the contents index lists
inside the case's images is present, never reported absent. Invented
fixtures only (CORP-WS01, jane.doe)."""
from __future__ import annotations

from core.evidence_profile import build_evidence_profile, format_profile_for_prompt
from tests.core.test_contents_index import WS01, _build, _image, _links, _plan, case  # noqa: F401


def _indexed(case, monkeypatch):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": WS01})


def test_event_logs_inside_an_image_are_present(case, monkeypatch):
    _indexed(case, monkeypatch)
    p = build_evidence_profile(case)
    assert "windows_eventlog" in p["present_classes"] and "windows_eventlog" not in p["absent_classes"]
    assert p["inside_images"]["windows_eventlog"] == {"files": 2, "hosts": 1,
                                                      "example_dir": "Windows/System32/winevt/Logs"}
    assert "email" in p["absent_classes"]
    assert ("windows_eventlog: 2 files inside 1 hosts' images (most under Windows/System32/winevt/Logs)"
            in format_profile_for_prompt(p))
    # The compat gate reads the corrected set.
    from tools.evidence_compat import check_tool_against_profile
    assert check_tool_against_profile("ez_ez_evtxecmd", {"present_classes": ["windows_eventlog"]}) is None


def test_off_the_profile_reads_the_case_files_only(case, monkeypatch):
    _indexed(case, monkeypatch)
    monkeypatch.setenv("ATLAS_PROFILE_INSIDE_IMAGES", "0")
    p = build_evidence_profile(case)
    assert "windows_eventlog" in p["absent_classes"] and not p["inside_images"]


def test_a_read_writing_the_index_does_not_rebuild_the_profile_a_relist_does(case, monkeypatch):
    from core import contents_index as ci
    from core.evidence_profile import ensure_evidence_profile
    _indexed(case, monkeypatch)
    first = ensure_evidence_profile(case)
    builds = []
    real = build_evidence_profile
    monkeypatch.setattr("core.evidence_profile.build_evidence_profile", lambda c: builds.append(1) or real(c))
    con = ci._connect(case)                                 # a mid-run write: partial rows shown
    con.execute("INSERT INTO partial (source_id, call_id, rows_shown) VALUES (1, 7, 3)")
    con.commit()
    con.close()
    assert ensure_evidence_profile(case)["listing_generation"] == first["listing_generation"] and not builds
    con = ci._connect(case)                                 # a relist: the listing changed
    ci._meta_set(con, "listing_generation", {"n": first["listing_generation"] + 1})
    con.commit()
    con.close()
    ensure_evidence_profile(case)
    assert builds == [1]
