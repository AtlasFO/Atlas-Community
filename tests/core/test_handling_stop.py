"""A handling stop: every tool has a class, the gate refuses what would copy,
render or disclose the material, the frames differ, and the stop is asserted
only on an asserted reading and lifted only by a human."""
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from core import handling_stop as H

JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00C\x00" + b"\x08" * 64 + b"\xff\xd9"


def _case(tmp_path, brief="**Case ID:** X\n**System owner:** victim\n"):
    d = tmp_path / "CASE"
    (d / ".atlas").mkdir(parents=True)
    (d / "CASE.md").write_text(brief, encoding="utf-8")
    return d


def _live_tool_names() -> set[str]:
    """The names the agent calls: the composed server mounts every tool module
    under a namespace of its own, which is what the middleware hands the gate."""
    import asyncio, inspect
    import server
    r = server.mcp.list_tools()
    tools = asyncio.run(r) if inspect.isawaitable(r) else r
    return {getattr(t, "name", t) for t in tools}


def test_every_registered_tool_has_a_class():
    names = _live_tool_names()
    assert len(names) > 300
    unclassified = sorted(n for n in names if H.tool_class(n) is None)
    assert unclassified == [], unclassified
    stale = sorted((H.ALLOWED_TOOLS | H.REFUSED_TOOLS | H.MEDIA_TOOLS | H.ONLINE_TOOLS) - names)
    assert stale == [], stale


def test_the_classes_follow_the_rule():
    assert H.tool_class("archive_zip_extract") == "refused" and H.tool_class("misc_pff_export") == "refused"
    assert H.tool_class("carve_foremost_carve") == "refused" and H.tool_class("tsk_tsk_recover") == "refused"
    assert H.tool_class("tsk_tsk_icat") == "media" and H.tool_class("strings_hexdump") == "media"
    assert H.tool_class("enrich_vt_lookup_hash") == "online"
    assert H.tool_class("hash_hash_directory") == "allowed" and H.tool_class("hash_hashdeep_compute") == "allowed"
    assert H.tool_class("misc_list_evidence_dir") == "allowed" and H.tool_class("yara_yara_scan_file") == "allowed"


def test_a_finding_asserts_the_stop_and_a_handling_instruction_does_not(tmp_path):
    from core.claim_graph import add_claim
    from core.ir_playbook import seed_from_intake
    from core.recommendations import derive_from_finding_text
    d = _case(tmp_path, "**Case ID:** X\n**System owner:** victim\n\n## What you already know\n"
                        "Atlas must not process CSAM; hand such material to the examiner.\n")
    seed_from_intake(d)
    assert H.state(d) is None
    text = "The profile folder held CSAM."
    c = add_claim(d, statement=text, confidence="CONFIRMED", host="PC01")["node_id"]
    derive_from_finding_text(d, c, text, host="PC01")
    st = H.state(d)
    assert st and st["class"] == "csam" and st["basis"] == c and st["frame"] == "incident" and st["device"] == "PC01"
    # asserted once: a second finding keeps the first assertion
    c2 = add_claim(d, statement="More CSAM in the cache.", confidence="LIKELY", host="PC02")["node_id"]
    derive_from_finding_text(d, c2, "More CSAM in the cache.", host="PC02")
    assert H.state(d)["basis"] == c
    assert "HANDLING STOP" in H.prompt_block(d) and "PC01" in H.prompt_block(d)


def test_the_brief_can_assert_the_stop(tmp_path):
    from core.ir_playbook import seed_from_intake
    d = _case(tmp_path, "**Case ID:** X\n**Engagement:** examination\n**System owner:** suspect\n\n"
                        "## Scenario\n\nThe seized laptop holds CSAM according to the referral.\n")
    seed_from_intake(d)
    st = H.state(d)
    assert st and st["basis"] == "intake" and st["frame"] == "subject" and st["device"] == ""


def test_the_gate_refuses_by_class_and_by_content(tmp_path):
    d = _case(tmp_path)
    H.assert_stop(d, "csam", "C0001", frame="subject")
    assert H.gate("archive_zip_extract", {"archive_path": "x.zip"}, d)
    assert H.gate("enrich_vt_lookup_hash", {"hash": "a" * 32}, d)
    assert H.gate("no_such_tool", {}, d)
    assert H.gate("hash_hash_directory", {"directory": str(d)}, d) is None
    assert H.gate("strings_exiftool_metadata", {"file_path": str(d / "CASE.md")}, d) is None
    assert H.gate("misc_list_evidence_dir", {"path": str(d)}, d) is None
    pic = d / "exports" / "renamed.dll"
    pic.parent.mkdir()
    pic.write_bytes(JPEG)
    txt = d / "exports" / "notes.txt"
    txt.write_text("plain text\n", encoding="utf-8")
    assert H.gate("strings_hexdump", {"file_path": str(pic)}, d)          # a picture, whatever its name
    assert H.gate("strings_hexdump", {"file_path": str(txt)}, d) is None
    assert H.gate("strings_read_text", {"file_path": str(d / "missing.jpg")}, d)   # an extension adds a refusal
    assert len(H.state(d)["refused"]) == 5 and H.record(d)["refused_count"] == 5


def test_an_inode_is_judged_by_its_bytes(tmp_path):
    d = _case(tmp_path)
    H.assert_stop(d, "csam", "C0001", frame="subject")

    with patch.object(H, "_icat_head", lambda *a, **k: JPEG):
        assert H.gate("tsk_tsk_icat", {"image": "disk.E01", "inode": "128-128-1", "output_path": "o"}, d)
    with patch.object(H, "_icat_head", lambda *a, **k: b"regf" + b"\x00" * 100):
        assert H.gate("tsk_tsk_icat", {"image": "disk.E01", "inode": "42", "output_path": "o"}, d) is None


def test_the_incident_frame_ends_the_devices_examination_and_the_subject_frame_continues(tmp_path):
    from core.evidence_links import empty_links, save_evidence_links
    d = _case(tmp_path)
    links = empty_links("X")
    links["entries"] += [{"label": "PC01", "kind": "disk", "path": "evidence/pc01.E01", "host": "PC01"},
                         {"label": "FS02", "kind": "disk", "path": "evidence/fs02.E01", "host": "FS02"}]
    save_evidence_links(d, links)
    (d / "evidence").mkdir()
    (d / "evidence" / "pc01.E01").write_bytes(b"\x00" * 16)
    (d / "evidence" / "fs02.E01").write_bytes(b"\x00" * 16)
    H.assert_stop(d, "csam", "C0001", frame="incident", device="PC01")
    assert H.gate("tsk_tsk_fls", {"image": str(d / "evidence" / "pc01.E01")}, d)
    assert H.gate("tsk_tsk_fls", {"image": str(d / "evidence" / "fs02.E01")}, d) is None
    assert H.gate("misc_record_finding", {"description": str(d / "evidence" / "pc01.E01")}, d) is None
    assert "PC01" in H.prompt_block(d) and any("handed over" in l for l in H.report_lines(d, "en"))
    s = _case(tmp_path / "subject", "**Case ID:** Y\n**System owner:** suspect\n")
    save_evidence_links(s, links)
    (s / "evidence").mkdir()
    (s / "evidence" / "pc01.E01").write_bytes(b"\x00" * 16)
    H.assert_stop(s, "csam", "C0001", frame="subject", device="PC01")
    assert H.gate("tsk_tsk_fls", {"image": str(s / "evidence" / "pc01.E01")}, s) is None


def test_a_fresh_start_and_the_dashboard_refuse_and_a_lifting_is_recorded(tmp_path):
    from tools.misc import clear_case_run
    d = _case(tmp_path)
    assert H.refuse_fresh_start(d) is None
    H.assert_stop(d, "csam", "intake", frame="subject")
    assert "exports/" in H.refuse_fresh_start(d)
    fn = getattr(clear_case_run, "fn", clear_case_run)
    assert fn(str(d)).get("gate") == "handling_stop"
    pic = d / "exports" / "carved" / "x.jpg"
    pic.parent.mkdir(parents=True)
    pic.write_bytes(JPEG)
    (d / "exports" / "carved" / "list.txt").write_text("x", encoding="utf-8")
    (d / "notes.txt").write_text("x", encoding="utf-8")
    # everything under the quarantined exports/, and media anywhere in the case
    assert H.dashboard_refuses(pic) and H.dashboard_refuses(d / "exports" / "carved" / "list.txt")
    assert not H.dashboard_refuses(d / "notes.txt") and not H.dashboard_refuses(tmp_path / "elsewhere.jpg")
    en, de = H.report_lines(d, "en"), H.report_lines(d, "de")
    assert en[0] == "**Handling**" and "in force" in en[1] and "quarantined" in en[3]
    assert de[0].startswith("**Umgang") and "in Kraft" in de[1]
    # a human lifts the stop: the record keeps both times, the gate opens
    H.stop_path(d).unlink()
    assert H.state(d) is None and H.record(d)["lifted_at"]
    assert H.gate("archive_zip_extract", {"archive_path": "x.zip"}, d) is None
    assert any("lifted at" in l for l in H.report_lines(d, "en")) and H.refuse_fresh_start(d) is None


def test_the_reviewed_holes_are_closed(tmp_path):
    from core.evidence_links import empty_links, save_evidence_links
    d = _case(tmp_path)
    (d / "evidence").mkdir()
    (d / "evidence" / "pc01.E01").write_bytes(b"\x00" * 16)
    H.assert_stop(d, "csam", "intake", frame="subject")
    # the stop file and its record are a human's
    assert "only a human" in H.gate("misc_write_case_document", {"path": str(H.stop_path(d))}, d)
    assert "only a human" in H.gate("misc_list_evidence_dir", {"path": str(H.record_path(d))}, d)
    # raw commands, the sorter's copies and velo collections are refused outright
    assert H.gate("misc_batch_run", {"argv": ["foremost", "-i", "x"], "force": True}, d)
    assert H.gate("tsk_tsk_sorter", {"image": "x"}, d) and H.gate("velo_query", {"vql": "SELECT 1"}, d)
    assert H.gate("velo_collect_artifact", {"artifact": "Windows.Search.FileFinder"}, d)
    # mail parsers keep their headers but never write attachments
    eml = d / "evidence" / "m.eml"
    eml.write_text("From: a@example.org\nSubject: x\n\nbody\n", encoding="utf-8")
    assert H.gate("misc_parse_email", {"eml_path": str(eml)}, d) is None
    assert "attachments" in H.gate("misc_parse_email", {"eml_path": str(eml), "extract_attachments_to": str(d / "out")}, d)
    # a live read of a picture is refused by its name, and by its bytes after the call
    assert H.gate("live_live_read_file", {"host": "h", "path": "C:\\Users\\x\\Pictures\\IMG_0001.JPG"}, d)
    assert H.gate("live_live_read_file", {"host": "h", "path": "/var/log/auth.log"}, d) is None
    assert H.post_gate("live_live_read_file", {}, {"success": True, "stdout": JPEG.decode("latin-1")}, d)
    assert H.post_gate("live_live_read_file", {}, {"success": True, "stdout": "Sep 27 sshd: accepted"}, d) is None
    import base64
    assert H.post_gate("crypto_decrypt", {}, {"decoded": base64.b64encode(JPEG + b"\x00" * 200).decode()}, d)
    assert H.post_gate("misc_list_evidence_dir", {}, {"stdout": JPEG.decode("latin-1")}, d) is None   # not media-gated
    # the icat peek fails closed
    with patch.object(H, "_icat_head", lambda *a, **k: b""):
        assert H.gate("tsk_tsk_icat", {"image": "disk.E01", "inode": "5", "output_path": "o"}, d)
    # the dashboard refuses everything under the quarantined exports/
    z = d / "exports" / "carved" / "pictures.zip"
    z.parent.mkdir(parents=True)
    z.write_bytes(b"PK\x03\x04" + b"\x00" * 30)
    assert H.dashboard_refuses(z) and not H.dashboard_refuses(d / "evidence" / "m.eml")


def test_an_intake_stop_in_the_incident_frame_hands_over_all_evidence(tmp_path):
    from core.evidence_links import empty_links, save_evidence_links
    d = _case(tmp_path)
    links = empty_links("X")
    links["entries"] += [{"label": "PC01", "kind": "disk", "path": "evidence/pc01.E01", "host": "PC01"}]
    save_evidence_links(d, links)
    (d / "evidence").mkdir()
    (d / "evidence" / "pc01.E01").write_bytes(b"\x00" * 16)
    H.assert_stop(d, "csam", "intake", frame="incident")
    r = H.gate("tsk_tsk_fls", {"image": str(d / "evidence" / "pc01.E01")}, d)
    assert r and "all evidence was handed over" in r
    assert H.gate("misc_record_finding", {"description": "x"}, d) is None
    assert "all evidence is handed over" in H.prompt_block(d) and any("all evidence" in l for l in H.report_lines(d, "en"))
    # a device that matches no evidence entry hands over all evidence too
    e = _case(tmp_path / "e")
    save_evidence_links(e, links)
    (e / "evidence").mkdir()
    (e / "evidence" / "pc01.E01").write_bytes(b"\x00" * 16)
    H.assert_stop(e, "csam", "C0001", frame="incident", device="GHOST")
    assert "all evidence was handed over" in H.gate("tsk_tsk_fls", {"image": str(e / "evidence" / "pc01.E01")}, e)


def test_the_names_the_agent_calls_are_classified_as_their_modules_are(tmp_path):
    d = _case(tmp_path)
    H.assert_stop(d, "csam", "C0001", frame="subject")
    note = d / "notes.txt"
    note.write_text("plain text\n", encoding="utf-8")
    names = _live_tool_names()
    for name in ("hash_hash_file", "reason_reason_hypothesize", "tsk_tsk_fls", "vol_vol_pslist",
                 "archive_zip_extract", "carve_foremost_carve", "enrich_vt_lookup_hash"):
        assert name in names, name
    assert H.gate("hash_hash_file", {"file_path": str(note)}, d) is None
    assert H.gate("reason_reason_hypothesize", {"hypothesis": "x"}, d) is None
    assert "carves, extracts" in H.gate("archive_zip_extract", {"archive_path": "x.zip"}, d)
    assert "online lookup" in H.gate("enrich_vt_lookup_hash", {"hash": "a" * 32}, d)


def test_the_middleware_refuses_through_the_gate(tmp_path):
    d = _case(tmp_path)
    H.assert_stop(d, "csam", "C0001", frame="subject")
    with patch("core.claim_graph.resolve_case_dir", lambda *_a, **_k: str(d)):
        assert H.gate("carve_scalpel_carve", {"image_path": "x"}, str(d)).startswith("Tool carve_scalpel_carve refused")


def test_a_stop_asserted_in_a_mirror_also_stands_in_the_real_case(tmp_path):
    """An --output-dir run handles the real case's evidence through a
    symlink; a stop it asserts must outlive the mirror."""
    import json as _json
    from core import handling_stop as hs
    real = tmp_path / "real"
    (real / ".atlas").mkdir(parents=True)
    mirror = tmp_path / "mirror"
    (mirror / ".atlas").mkdir(parents=True)
    (mirror / ".atlas" / hs.MIRROR_MARKER).write_text(
        _json.dumps({"real_case": str(real)}), encoding="utf-8")
    hs.assert_stop(mirror, "csam", "C0007", frame="subject")
    assert hs.is_stopped(mirror) and hs.is_stopped(real)
    assert hs.state(real)["basis"] == "C0007"
    # A case that is no mirror asserts only in itself.
    other = tmp_path / "other"
    (other / ".atlas").mkdir(parents=True)
    hs.assert_stop(other, "csam", "intake", frame="subject")
    assert hs.is_stopped(other)
