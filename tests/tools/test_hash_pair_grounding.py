"""A finding that binds a file to a hash rests on a row that shows them
together (tools._gates.citation_support.hash_pairs, unshown_pairs; the
record gate tools._gates.hash_pair_grounding; the pair branch of
citation_status). Invented fixtures only (CORP-WS01, jane.doe, digests of no
file)."""
from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from tools._gates import GateContext
from tools._gates import citation_support as cs
from tools._gates import hash_pair_grounding as hpg

H1 = hashlib.md5(b"r10 pair fixture one").hexdigest()
H2 = hashlib.md5(b"r10 pair fixture two").hexdigest()
S1 = hashlib.sha256(b"r10 pair fixture three").hexdigest()


def _manifest(cid, rows):
    return {"type": "tool_call", "call_id": cid, "cmd": "<py>:table_table_grep", "success": True,
            "evidence_ref": "analysis/manifest.csv",
            "args": json.dumps({"path": "analysis/manifest.csv", "pattern": "jpg"}),
            "stdout_excerpt": json.dumps({"success": True, "path": "analysis/manifest.csv", "pattern": "jpg",
                                          "hits": rows, "hit_count": len(rows)})}


def _hash_record(cid, path, sha256, same=()):
    out = {"success": True, "file": path, "size_bytes": 4096, "sha256": sha256}
    if same:
        out["identical_to"] = [{"path": p, "source": "analysis"} for p in same]
    return {"type": "tool_call", "call_id": cid, "cmd": "<py>:hash_hash_file", "success": True,
            "evidence_ref": path, "args": json.dumps({"file_path": path}), "stdout_excerpt": json.dumps(out)}


def _ctx(description, calls, cited, tier="LIKELY"):
    by = {c["call_id"]: c for c in calls}
    return GateContext(
        description=description, confidence=tier.capitalize(), tier=tier, source="test",
        linked_call_id=0, tested_hypothesis_id="", log=SimpleNamespace(_entries=list(calls)),
        idx=SimpleNamespace(by_call_id=by, by_type={}), window=[], input_call_ids=list(cited))


@pytest.fixture(autouse=True)
def _rows(monkeypatch):
    monkeypatch.setattr(cs, "_ROW_CACHE", {})


def test_pairs_are_read_per_clause():
    assert cs.hash_pairs(f"carve/jpg/00001.jpg and 00002.jpg share MD5 {H1} in the manifest") == [
        (H1, ("00001.jpg", "00002.jpg"))]
    assert cs.hash_pairs(f"C:/Users/jane.doe/Downloads/tool(1).exe and tool.exe have MD5 {H1}.") == [
        (H1, ("tool(1).exe", "tool.exe"))]
    # A name set off by a comma, an abbreviated digest, two digests: no pair.
    assert cs.hash_pairs(f"report.pdf has SHA256 {S1}, extracted from export.zip") == [(S1, ("report.pdf",))]
    assert cs.hash_pairs(f"a.exe has MD5 {H1[:8]}") == []
    assert cs.hash_pairs(f"a.exe and b.exe have MD5 {H1} and {H2}") == []


def test_a_name_never_shown_with_the_hash_is_refused():
    m = _manifest(5, [{"path": "carve/jpg/00001.jpg", "md5": H1}, {"path": "carve/jpg/00002.jpg", "md5": H2}])
    out = hpg.check(_ctx(f"00001.jpg and 00002.jpg share MD5 {H1} in the manifest", [m], [5]))
    assert out is not None and out["gate"] == "hash_pair_grounding"
    assert "00002.jpg" in out["error"] and "00001.jpg" not in out["error"] and "SUSPECTED" in out["error"]


def test_every_name_shown_with_the_hash_passes():
    m = _manifest(5, [{"path": "carve/jpg/00001.jpg", "md5": H1}, {"path": "carve/jpg/00002.jpg", "md5": H1}])
    assert hpg.check(_ctx(f"00001.jpg and 00002.jpg share MD5 {H1} in the manifest", [m], [5])) is None


def test_suspected_is_not_refused():
    m = _manifest(5, [{"path": "carve/jpg/00001.jpg", "md5": H2}])
    assert hpg.check(_ctx(f"00001.jpg has MD5 {H1}", [m], [5], tier="SUSPECTED")) is None


def test_a_record_result_is_one_row():
    """A hash of one file beside the files of the same content: the call
    says all of them have the digest."""
    r = _hash_record(7, "analysis/export/report.pdf", S1, same=["analysis/carve/copy.pdf"])
    assert hpg.check(_ctx(f"report.pdf and copy.pdf have SHA256 {S1}", [r], [7])) is None
    assert hpg.check(_ctx(f"report.pdf and other.pdf have SHA256 {S1}", [r], [7])) is not None


def test_an_uncited_call_that_shows_the_pair_passes_as_located():
    """The cited row shows the digest beside another file; an earlier call
    shows it beside the named one."""
    wrong = _manifest(5, [{"path": "carve/jpg/00009.jpg", "md5": H1}])
    right = _manifest(3, [{"path": "carve/jpg/00001.jpg", "md5": H1}])
    desc = f"00001.jpg has MD5 {H1}"
    assert hpg.check(_ctx(desc, [right, wrong], [5])) is None
    status, located, detail = cs.citation_status(desc, [wrong], [], "", [right, wrong])
    assert status == "located" and located == [3] and "call 3 shows 00001.jpg" in detail


def test_the_report_check_says_a_later_call_ran_after_the_finding():
    wrong = _manifest(5, [{"path": "carve/jpg/00009.jpg", "md5": H1}])
    later = _manifest(12, [{"path": "carve/jpg/00001.jpg", "md5": H1}])
    desc = f"00001.jpg has MD5 {H1}"
    status, located, detail = cs.citation_status(desc, [wrong], [], "", [wrong, later], finding_call_id=8)
    assert status == "located" and located == [12]
    assert "call 12, which ran after this finding, shows 00001.jpg" in detail
    status, _l, detail = cs.citation_status(desc, [wrong], [], "", [wrong])
    assert status == "not_shown" and "no call shows 00001.jpg" in detail


def test_the_gaps_line_names_the_pair():
    from core.report_projection import _citation_gap_line
    n = {"citation_status": "not_shown", "citation_detail": f"a hash bound to a file: no call shows 00001.jpg with {H1[:16]} in one row"}
    assert _citation_gap_line(n, "F-003", "x") == f"F-003: {n['citation_detail']}."


def test_the_detail_is_kept_on_the_claim_and_cleared(tmp_path):
    import core.claim_graph as cg
    (tmp_path / ".atlas").mkdir()
    nid = cg.add_claim(tmp_path, statement=f"00001.jpg has MD5 {H1}", confidence="SUSPECTED", host="CORP-WS01")["node_id"]
    cg.set_citation_status(tmp_path, nid, "not_shown", [], detail="a hash bound to a file: no call shows it")
    assert cg.get_node(cg.load_graph(tmp_path), nid)["citation_detail"].startswith("a hash bound")
    cg.set_citation_status(tmp_path, nid, "cited", [])
    assert "citation_detail" not in cg.get_node(cg.load_graph(tmp_path), nid)


def test_the_gate_runs_at_record_time():
    from tools._gates import GATES
    names = [n for n, _f in GATES]
    assert names.index("hash_pair_grounding") == names.index("instruction_text_grounding") + 1


def _hash_folder(cid, records):
    out = {"success": True, "directory": "analysis/carve", "algorithm": "md5", "file_count": len(records),
           "cache_hits": 0, "identical_files": 0, "hashes": records, "errors": [], "manifest": None}
    return {"type": "tool_call", "call_id": cid, "cmd": "<py>:hash_hash_directory", "success": True,
            "evidence_ref": "analysis/carve", "args": json.dumps({"directory": "analysis/carve"}),
            "stdout_excerpt": json.dumps(out)}


def test_a_folder_of_hashes_keeps_one_row_per_file():
    """Each record of a folder's hashes carries its own digest: the records
    are rows, never one record."""
    d = _hash_folder(4, [{"file": "analysis/carve/00001.jpg", "md5": H1},
                         {"file": "analysis/carve/00002.jpg", "md5": H2}])
    assert hpg.check(_ctx(f"00001.jpg and 00002.jpg share MD5 {H1}", [d], [4])) is not None
    same = _hash_folder(4, [{"file": "analysis/carve/00001.jpg", "md5": H1,
                             "identical_to": ["analysis/carve/00002.jpg"]}])
    assert hpg.check(_ctx(f"00001.jpg and 00002.jpg share MD5 {H1}", [same], [4])) is None


def test_a_file_written_with_its_own_digest_is_checked():
    m = _manifest(5, [{"path": "carve/jpg/00001.jpg", "md5": H1}, {"path": "carve/jpg/00002.jpg", "md5": H2}])
    right = f"Two JPEGs: carve/jpg/00001.jpg (MD5 {H1}, 4096 bytes) and carve/jpg/00002.jpg (MD5 {H2}, 4096 bytes)."
    wrong = f"Two identical JPEGs: carve/jpg/00001.jpg (MD5 {H1}) and carve/jpg/00002.jpg (MD5: {H1})."
    assert cs.hash_pairs(right) == [(H1, ("00001.jpg",)), (H2, ("00002.jpg",))]
    assert hpg.check(_ctx(right, [m], [5])) is None
    out = hpg.check(_ctx(wrong, [m], [5]))
    assert out is not None and "00002.jpg" in out["error"] and "'name.ext (MD5 ...)'" in out["error"]
    # A digest written with its file.
    assert cs.hash_pairs(f"The digest {H2} (00002.jpg) matches no other file") == [(H2, ("00002.jpg",))]
    assert hpg.check(_ctx(f"The digest {H1} (00002.jpg) matches no other file", [m], [5])) is not None


def test_known_false_refusals_are_pinned():
    """Known issue: a second file the clause names for another reason is
    held to the digest too (the extraction source, the parent process)."""
    rec = _hash_record(7, "analysis/export/tool.exe", S1)
    for desc in (f"{S1} is the SHA256 of tool.exe extracted from export.zip",
                 f"tool.exe launched by services.exe has SHA256 {S1}"):
        assert len(cs.hash_pairs(desc)[0][1]) == 2
        assert hpg.check(_ctx(desc, [rec], [7])) is not None


def test_a_suspected_pair_no_call_shows_is_told_so(tmp_path, monkeypatch):
    from unittest.mock import patch
    from core.execution_log import ExecutionLog
    from tools.misc import record_finding
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
    lg = ExecutionLog()
    lg.configure("CASE-A", str(tmp_path / "trace.json"), save_session=False)
    lg.record_dair_call("Analyze", "", False, "", "", "stay", "")
    cid = lg.record_tool_call("<py>:table_table_grep", True, False, 0, 0, stdout_excerpt=json.dumps(
        {"success": True, "hits": [{"path": "carve/jpg/00001.jpg", "md5": H1},
                                   {"path": "carve/jpg/00002.jpg", "md5": H2}], "hit_count": 2}))
    with patch("core.execution_log.log", lg):
        r = record_finding(f"00001.jpg and 00002.jpg share MD5 {H1} in the manifest", "SUSPECTED", "table.table_grep",
                           linked_call_id=cid, input_call_ids=[cid], supporting_evidence="the manifest rows")
    assert r["success"] is True
    assert str(r.get("citation") or "").startswith("a hash bound to a file: no call shows 00002.jpg")
