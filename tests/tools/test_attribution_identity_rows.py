"""ATLAS_ATTRIBUTION_IDENTITY_ROWS: an attribution verdict at
CONFIRMED or LIKELY passes when a call it cites prints the credited account
or person in a row beside another term of the claim; the refusal lists the
trace calls whose rows show that and names no record type. Invented
fixtures only (CORP-WS01, CORP\\jdoe, jane.doe, archive.zip, 203.0.113.7,
dates in 2031)."""
from __future__ import annotations

import re
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from tools._gates import GateContext
from tools._gates import named_actor_attribution_grounding as nag
from tools._gates import principal_attribution_grounding as pag


@pytest.fixture(autouse=True)
def _on(monkeypatch):
    monkeypatch.setenv("ATLAS_ATTRIBUTION_IDENTITY_ROWS", "1")
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
    monkeypatch.setenv("ATLAS_EXTERNAL_LOOKUP_FIRST", "1")


def _call(cid, out, tool="table_table_grep"):
    return {"type": "tool_call", "call_id": cid, "cmd": f"<py>:{tool}", "mcp_tool": tool, "success": True,
            "stdout_excerpt": out, "args": '{"path": "evidence/timeline.csv", "pattern": "x"}'}


def _ctx(description, calls, cite, tier="LIKELY", supporting_evidence=""):
    by_id = {c["call_id"]: c for c in calls}
    return GateContext(description=description, confidence=tier.capitalize(), tier=tier, source="t",
                       linked_call_id=0, tested_hypothesis_id="", log=MagicMock(),
                       idx=SimpleNamespace(by_call_id=by_id, by_type={"tool_call": calls}), window=[],
                       input_call_ids=cite, supporting_evidence=supporting_evidence)


LOGON = _call(4, "2031-01-04 09:12:00,CORP-WS01,logon,CORP\\jdoe,203.0.113.7")
LISTING = _call(5, "C:\\Users\\jdoe\nC:\\Users\\Public")
ADDRESS = _call(6, "2031-01-04 09:12:00 connection from 203.0.113.7")
ARCHIVE = _call(7, "2031-01-04 09:40:00,CORP-WS01,file created,jane.doe,C:\\Temp\\archive.zip")
JANET = _call(8, "2031-01-04 09:40:00,CORP-WS01,file created,janet,C:\\Temp\\archive.zip")

ACCOUNT_CLAIM = "The account CORP\\jdoe was used by Jane Doe to log on to CORP-WS01 at 2031-01-04 09:12"


def test_a_cited_row_with_the_account_and_the_act_passes():
    assert pag.check(_ctx(ACCOUNT_CLAIM, [LOGON, LISTING, ADDRESS], [4])) is None


def test_a_listing_or_an_address_alone_is_refused_with_the_calls_that_show_it():
    out = pag.check(_ctx(ACCOUNT_CLAIM, [LOGON, LISTING, ADDRESS], [6]))
    assert out and out["gate"] == "principal_attribution_grounding" and "#4" in out["error"]
    assert "cited: #6" in out["error"]
    out = pag.check(_ctx(ACCOUNT_CLAIM, [LISTING], [5], supporting_evidence="logon of CORP\\jdoe at 09:12"))
    assert out and "No call in the trace prints" in out["error"]


def test_a_person_matches_their_account_spellings():
    claim = "Jane Doe exfiltrated archive.zip from CORP-WS01"
    assert nag.check(_ctx(claim, [ARCHIVE, JANET], [7])) is None
    out = nag.check(_ctx(claim, [ARCHIVE, JANET], [8]))
    assert out and "#7" in out["error"]


def test_a_bare_first_name_gets_the_account_hint():
    out = nag.check(_ctx("Jane exfiltrated archive.zip", [JANET], [8]))
    assert out and "write the account the evidence prints" in out["error"]


def test_the_refusal_names_no_event_id_and_no_parser():
    out = pag.check(_ctx(ACCOUNT_CLAIM, [LISTING], [5]))
    assert not re.search(r"\b4\d{3}\b", out["error"]) and "evtxecmd" not in out["error"]


def test_the_switch_off_keeps_the_session_vocabulary_test(monkeypatch):
    monkeypatch.setenv("ATLAS_ATTRIBUTION_IDENTITY_ROWS", "0")
    out = pag.check(_ctx(ACCOUNT_CLAIM, [LISTING], [5], supporting_evidence="no session"))
    assert out and "logon-session binding" in out["error"]


def test_no_record_type_is_baked_into_the_row_test():
    from pathlib import Path
    import tools._gates._identity_rows as rows
    import core.attribution_identity as ai
    for mod in (rows, ai):
        text = Path(mod.__file__).read_text(encoding="utf-8")
        assert not re.search(r"\b(?:4[67]\d\d|1102)\b", text)
        assert not re.search(r"(?i)evtxecmd|security\.evtx|logon type", text)
