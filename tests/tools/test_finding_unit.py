"""One finding states one fact (tools.misc.record_finding): several facts
are several findings, also when one output or one quotation shows them all,
and a link between two artifacts is one finding that cites both sides.
Sibling parts recorded side by side stand as findings of their own: the
near-duplicate guard folds none of them and the pre-report pairs list none.
A CONFIRMED statement of several sentences whose cited rows show only some
of its values is told that a separate fact is a finding of its own.
Invented fixtures only."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog

NOTES = ["I wiped the old laptop on Friday before the audit",
         "I moved the archive to the backup share at night",
         "the vpn account was set up for me by jane.doe"]
PARTS = [f'notes.txt on CORP-WS01 says "{line}".' for line in NOTES]
WEB = ["2031-03-04 09:12:49 jane.doe GET http://files.example.com/a.zip 203.0.113.10",
       "2031-03-04 09:40:02 jane.doe GET http://files.example.com/b.zip 203.0.113.10"]
DOWNLOADS = ["web.log on CORP-WS01 shows jane.doe downloading a.zip from 203.0.113.10 at 2031-03-04 09:12.",
             "web.log on CORP-WS01 shows jane.doe downloading b.zip from 203.0.113.10 at 2031-03-04 09:40."]
SHA = "9f2c" * 16


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
    with patch("tools.misc.tool_program", side_effect=lambda name, *rest: f"/usr/local/bin/{name}"):
        yield


@pytest.fixture
def case(tmp_path):
    case = tmp_path / "CASE-A"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / ".atlas" / "evidence_inventory.json").write_text(json.dumps({"complete": True, "summary": {}}))
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-WS01", "path": "evidence/ws01", "kind": "folder"}], "hosts": ["CORP-WS01"]}))
    return case


@pytest.fixture
def log(case):
    from core import provenance
    lg = ExecutionLog()
    lg.configure("CASE-A", str(case / "analysis" / "trace.json"), save_session=False)
    lg.record_dair_call("Analyze", "", False, "", "", "stay", "")
    provenance.reset_cache()
    return lg


def _lines(log, lines, path):
    cid = log.record_tool_call("<py>:strings_strings_grep", True, False, 0, 0,
                               stdout_excerpt=json.dumps({"success": True, "file": path, "pattern": "x",
                                                          "match_count": len(lines), "matches": lines}),
                               evidence_ref=path)
    log.annotate_tool_call(cid, args=json.dumps({"file_path": path, "pattern": "x"}))
    return cid


def _hash(log, path):
    cid = log.record_tool_call("<py>:hash_hash_file", True, False, 0, 0,
                               stdout_excerpt=json.dumps({"success": True, "path": path, "sha256": SHA,
                                                          "size": 4096}),
                               evidence_ref=path)
    log.annotate_tool_call(cid, args=json.dumps({"file_path": path}))
    return cid


def _record(log, case, statement, cids, confidence="LIKELY", **kw):
    from tools.misc import record_finding
    with patch("core.execution_log.log", log), \
            patch("core.claim_graph.resolve_case_dir", return_value=str(case)), \
            patch("tools._gates.contracts.failures", lambda name, ctx: []):
        return record_finding(statement, confidence, "strings", host="CORP-WS01", linked_call_id=cids[0],
                              input_call_ids=list(cids), supporting_evidence=statement, **kw)


def _pairs(case):
    from core.claim_graph import load_graph
    from tools.misc import standing_duplicate_pairs
    return standing_duplicate_pairs(load_graph(str(case)).get("nodes") or {})


def _standing(case, log):
    from core.claim_graph import asserted_finding_entries
    return asserted_finding_entries([e for e in log._entries if e.get("type") == "finding"], str(case))


def test_the_contract_states_the_unit_of_a_finding_on_its_description_field():
    """The unit is told where the model writes the finding, the description
    parameter, so the tool's own description (cut at the provider bound)
    keeps what it showed before."""
    import asyncio
    import tools.misc as M
    from core.tool_text import model_description
    tool = asyncio.run(M.mcp.get_tool("record_finding"))
    text, schema = model_description(tool.description or "", dict(tool.parameters))
    field = " ".join(schema["properties"]["description"]["description"].split())
    assert field.startswith("one fact:") and "Several facts are several findings" in field
    assert "a link between two artifacts (one finding citing both)" in field
    text = " ".join(text.split())
    assert "Several facts" not in text and "so one corrected call can clear them all" in text


def test_the_system_prompt_records_each_fact_on_its_own():
    import agent.prompts as P
    src = " ".join(open(P.__file__, encoding="utf-8").read().split())
    assert "record each fact it \" \"shows as its own misc_record_finding, several in one turn. \" \"Record promptly" in src


def _clean(r):
    return r.get("success") is True and not ({"restates_call_id", "refines_call_id", "duplicate", "near_duplicate_of"} & set(r))


def test_three_facts_of_one_quotation_stand_as_three_findings(case, log):
    cid = _lines(log, NOTES, "analysis/ws01/notes.txt")
    results = [_record(log, case, p, [cid]) for p in PARTS]
    assert all(_clean(r) for r in results), results
    assert len(_standing(case, log)) == 3
    assert _pairs(case) == []


def test_templated_siblings_on_different_files_stand_side_by_side(case, log):
    """The second sibling carries the first one's words and adds a file: no
    sharper version of it, since it lacks the first one's time."""
    cid = _lines(log, WEB, "analysis/ws01/web.log")
    results = [_record(log, case, d, [cid]) for d in DOWNLOADS]
    assert all(_clean(r) for r in results), results
    assert len(_standing(case, log)) == 2
    assert _pairs(case) == []


def test_numberless_siblings_on_different_files_stand_side_by_side(case, log):
    """No time, address or count in either: the file each names tells the
    sibling apart from a sharper version of the other."""
    cid = _lines(log, ["web.log jane.doe GET http://files.example.com/a.zip",
                       "web.log jane.doe GET http://files.example.com/b.zip"], "analysis/ws01/web.log")
    texts = ["web.log on CORP-WS01 shows jane.doe downloading a.zip from files.example.com.",
             "web.log on CORP-WS01 shows jane.doe downloading b.zip from files.example.com."]
    from tools.misc import _relation
    assert _relation(texts[1], texts[0], elaborates=True)[0] == "refines"     # the guard's own word test
    results = [_record(log, case, t, [cid]) for t in texts]
    assert all(_clean(r) for r in results), results
    assert _pairs(case) == []


def test_a_refinement_that_keeps_the_older_files_and_numbers_is_still_named(case, log):
    from tools.misc import _another_fact
    old = "web.log on CORP-WS01 shows jane.doe downloading a.zip from files.example.com."
    assert not _another_fact(old.replace("files.example.com.", "files.example.com at 2031-03-04 09:12."), old)
    assert _another_fact(old.replace("a.zip", "b.zip"), old)


def test_the_split_advice_survives_the_error_bound(case, log):
    """The model reads the result's citation, whole; the trace keeps the
    error cut to 400 characters before the advice, so a long list of
    unshown values cannot push the advice out of either."""
    cid = _lines(log, NOTES[:1], "analysis/ws01/notes.txt")
    extra = " ".join(f"It also reached 203.0.113.{n} at 2031-03-04 10:{n:02d}." for n in range(10, 22))
    r = _record(log, case, PARTS[0] + " " + extra, [cid], confidence="CONFIRMED")
    tail = "the facts these rows show can be CONFIRMED on their own."
    assert r["success"] is True and r["confidence"] == "LIKELY" and r["citation"].endswith(tail)
    entry = next(e for e in log._entries if e.get("call_id") == r["_atlas_call_id"])
    err = entry["tier_auto_downgrade_error"]
    assert len(err) <= 400 and err.endswith(tail)


def test_a_bundle_split_by_superseding_it_leaves_every_part_standing(case, log):
    cid = _lines(log, NOTES, "analysis/ws01/notes.txt")
    bundle = _record(log, case, " ".join(PARTS), [cid])
    assert bundle["success"] is True
    first = _record(log, case, PARTS[0], [cid], supersedes=str(bundle["_atlas_call_id"]))
    rest = [_record(log, case, p, [cid]) for p in PARTS[1:]]
    assert first["success"] is True and all(_clean(r) for r in rest), rest
    standing = {e["call_id"] for e in _standing(case, log)}
    assert bundle["_atlas_call_id"] not in standing
    assert {first["_atlas_call_id"], *(r["_atlas_call_id"] for r in rest)} <= standing


def test_a_link_citing_both_sides_records_whole_and_confirmed(case, log):
    a = _hash(log, "exports/zip/photo2.jpg")
    b = _hash(log, "exports/carve/00001234.jpg")
    link = (f"photo2.jpg extracted from the archive and carved 00001234.jpg are the same file: "
            f"both have SHA256 {SHA}.")
    with patch("tools.misc._auto_evaluate", return_value={"auto": True, "verdict": "SUPPORTED"}):
        r = _record(log, case, link, [a, b], confidence="CONFIRMED")
    assert r["success"] is True and "tier_auto_downgrade_reason" not in r


def test_a_partly_shown_statement_of_several_sentences_is_told_to_record_its_parts(case, log):
    cid = _lines(log, NOTES[:1], "analysis/ws01/notes.txt")
    _lines(log, ["2031-03-04 09:12:49 jane.doe GET http://files.example.com/a.zip 203.0.113.10"],
           "analysis/ws01/web.log")
    r = _record(log, case, PARTS[0] + " jane.doe then downloaded a.zip from 203.0.113.10.", [cid],
                confidence="CONFIRMED")
    assert r["confidence"] == "LIKELY" and r["tier_auto_downgrade_reason"] == "citation_values_not_shown"
    assert "A sentence that states a separate fact is a finding of its own" in r["citation"]


def test_one_sentence_or_nothing_shown_gets_no_split_advice(case, log):
    cid = _lines(log, NOTES[:1], "analysis/ws01/notes.txt")
    one = _record(log, case, "notes.txt on CORP-WS01 names 203.0.113.99.", [cid], confidence="CONFIRMED")
    assert one["confidence"] == "LIKELY" and "finding of its own" not in one["citation"]
    none = _record(log, case, "jane.doe used 203.0.113.98. She later used 203.0.113.97.", [cid],
                   confidence="CONFIRMED")
    assert none["confidence"] == "LIKELY" and "finding of its own" not in none["citation"]
