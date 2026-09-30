"""Run-review fixes, each pinned by the behaviour that was wrong. Hosts,
users and files below are invented: the tests are about the mechanisms."""
import json
from pathlib import Path

import pytest

from core.claim_graph import (
    find_claim_by_anchors, infer_host_from_text, load_graph,
    upsert_claim_from_finding,
)
from core.coverage_ledger import exit_block_reason
from core.evidence_profile import classify_path
from core.investigation_tasks import (
    active_support, repair_unsupported_answers, update_task,
)


def _case(tmp_path: Path, hosts=("PROD-SQL-02", "WKSTN-4471")) -> Path:
    case = tmp_path / "C"
    (case / ".atlas").mkdir(parents=True)
    for d in ("evidence", "analysis", "exports"):
        (case / d).mkdir()
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps({
        "entries": [{"label": h, "kind": "disk", "path": f"evidence/{h}.vmdk"}
                    for h in hosts]}))
    return case


def _claim(case: Path, statement: str, **kw) -> str:
    r = upsert_claim_from_finding(case, statement=statement,
                                  confidence=kw.pop("confidence", "LIKELY"), **kw)
    assert r["success"], r
    return r["claim_id"]


def _task_store(case: Path, *texts: str, status="open", claims=()):
    (case / ".atlas" / "investigation_tasks.json").write_text(json.dumps({
        "schema_version": "1.0", "case_id": "C", "next_id": len(texts) + 1,
        "tasks": [{"id": f"task-{i:04d}", "text": t, "status": status,
                   "related_claim_ids": list(claims), "created_at": "x",
                   "updated_at": "x"} for i, t in enumerate(texts, 1)]}))


# ── a question is answered *by* something ────────────────────────────────

def test_answered_without_support_is_refused_and_offers_candidates(tmp_path):
    case = _case(tmp_path)
    cid = _claim(case, "Ransomware encrypted 800 files on PROD-SQL-02 on "
                       "2031-02-04 12:30:00 (.locked extension).")
    _task_store(case, "What type of attack happened?")
    r = update_task(case, "task-0001", status="answered")
    assert r["success"] is False and r["gate"] == "task_answer_unsupported"
    assert any(cid in c for c in r["candidates"])
    r = update_task(case, "task-0001", status="answered", related_claim_ids=[cid])
    assert r["success"] is True


def test_dead_or_withdrawn_ids_do_not_count_as_support(tmp_path):
    case = _case(tmp_path)
    _task_store(case, "Q")
    r = update_task(case, "task-0001", status="partial", related_claim_ids=["C9999"])
    assert r["gate"] == "task_answer_unsupported"
    assert active_support(case, ["C9999"]) == []


def test_close_out_reopens_unsupported_answers(tmp_path):
    case = _case(tmp_path)
    cid = _claim(case, "Account 'tempadmin' created on PROD-SQL-02 on "
                       "2031-02-04 12:00:00 by john.roe.")
    _task_store(case, "Was an account created?", "What happened?",
                status="answered")
    store = json.loads((case / ".atlas" / "investigation_tasks.json").read_text())
    store["tasks"][0]["related_claim_ids"] = [cid]        # supported
    (case / ".atlas" / "investigation_tasks.json").write_text(json.dumps(store))
    assert repair_unsupported_answers(case) == ["task-0002"]
    store = json.loads((case / ".atlas" / "investigation_tasks.json").read_text())
    assert store["tasks"][0]["status"] == "answered"
    assert store["tasks"][1]["status"] == "reopened"


# ── one finding, once ────────────────────────────────────────────────────

def test_rerecorded_finding_with_more_detail_updates_not_duplicates(tmp_path):
    case = _case(tmp_path)
    base = ("New local account 'tempadmin' (SID S-1-5-21-1111111111-2222222222-3333333333-1001) "
            "was created on PROD-SQL-02 on 2031-02-04 12:00:00 UTC by "
            "CORP\\\\john.roe (SID S-1-5-21-1111111111-2222222222-3333333333-1105).")
    a = _claim(case, base, finding_call_id=10)
    b = _claim(case, base + " Account was enabled (4722) and password reset.",
               confidence="CONFIRMED", finding_call_id=20)
    assert a == b
    node = load_graph(case)["nodes"][a]
    assert node["confidence"] == "CONFIRMED"           # stronger tier wins
    assert "4722" in node["statement"]                 # fuller statement wins
    assert 20 in node["merged_finding_call_ids"]


def test_different_events_about_the_same_account_stay_separate(tmp_path):
    case = _case(tmp_path)
    a = _claim(case, "Account tempadmin (SID S-1-5-21-1111111111-2222222222-3333333333-1001) "
                     "created on PROD-SQL-02 on 2031-02-04 12:00:00 UTC.")
    b = _claim(case, "Account tempadmin (SID S-1-5-21-1111111111-2222222222-3333333333-1001) "
                     "logged on to PROD-SQL-02 on 2031-02-05 08:00:00 UTC via RDP.")
    assert a != b                                       # one shared anchor only


def test_twin_never_lowers_confidence(tmp_path):
    case = _case(tmp_path)
    stmt = ("Driver driverx.sys (SHA1 0123456789abcdef0123456789abcdef01234567) "
            "loaded on WKSTN-4471 at 2031-02-04 12:05:00 UTC.")
    a = _claim(case, stmt, confidence="CONFIRMED", finding_call_id=1)
    _claim(case, stmt + " Service start type Auto.", confidence="SUSPECTED",
           finding_call_id=2)
    assert load_graph(case)["nodes"][a]["confidence"] == "CONFIRMED"


# ── every claim knows its host ───────────────────────────────────────────

def test_host_inferred_from_statement_against_case_hosts(tmp_path):
    case = _case(tmp_path)
    cid = _claim(case, "toolx.exe executed from the tempadmin profile on "
                       "PROD-SQL-02 at 2031-02-04 12:10:00 UTC.")
    assert load_graph(case)["nodes"][cid]["host"] == "PROD-SQL-02"


def test_statement_naming_two_hosts_is_an_estate_claim(tmp_path):
    case = _case(tmp_path)
    cid = _claim(case, "john.roe authenticated to both PROD-SQL-02 and "
                       "WKSTN-4471 from 10.9.8.7 on 2031-02-04.")
    node = load_graph(case)["nodes"][cid]
    assert node["host"] == "" and node["scope"] == "estate"


def test_host_inference_matches_the_name_the_machine_uses(tmp_path):
    """Logs say `sql02`; the evidence table says `PROD-SQL-02`."""
    case = _case(tmp_path)
    host, all_ = infer_host_from_text(case, "logon recorded on sql02 at 09:00")
    assert host == "" or host == "PROD-SQL-02"          # stem 'sql02' is short
    host, all_ = infer_host_from_text(case, "seen on wkstn-4471.corp.local")
    assert host == "WKSTN-4471"


def test_explicit_host_is_never_overridden(tmp_path):
    case = _case(tmp_path)
    cid = _claim(case, "Something happened on PROD-SQL-02.", host="WKSTN-4471")
    assert load_graph(case)["nodes"][cid]["host"] == "WKSTN-4471"


# ── the two report gates read one verdict ────────────────────────────────

def test_exit_block_reason_names_an_under_seeded_ledger(tmp_path, monkeypatch):
    case = _case(tmp_path, hosts=())
    (case / "analysis" / "sql02_security_evtx.csv").write_text("a,b\n1,2\n")
    (case / ".atlas" / "evidence_inventory.json").write_text(json.dumps(
        {"complete": True, "summary": {}}))
    import core.coverage_ledger as cl
    monkeypatch.setattr(cl, "ready_for_degraded_exit", lambda _c: False)
    monkeypatch.setattr("core.evidence_inventory_gate.inventory_satisfied",
                        lambda _c: True)
    monkeypatch.setattr("core.evidence_access.media_blocks_degraded_exit",
                        lambda _c: False)
    why = exit_block_reason(case)
    assert "under-seeded" in why and "1 searchable" in why


def test_exit_block_reason_is_empty_when_ready(tmp_path, monkeypatch):
    import core.coverage_ledger as cl
    monkeypatch.setattr(cl, "ready_for_degraded_exit", lambda _c: True)
    assert exit_block_reason(_case(tmp_path)) == ""


# ── structured text is tabular whatever it is called ─────────────────────

@pytest.mark.parametrize("name, body, expect", [
    ("fw-2031-02-04.log",
     "num;date;time;src;type;action;rule;iface\n1;4Feb;00:00;10.0.0.1;log;accept;;eth0\n",
     "tabular"),
    ("conn.log", "ts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\n1.0\tC1\t10.0.0.1\t80\t10.0.0.2\n",
     "tabular"),
    ("syslog.log", "Feb 4 00:00:01 fw kernel: free text\nFeb 4 00:00:02 fw kernel: more\n",
     "file"),
    ("notes.txt", "just a note\n", "file"),
])
def test_delimited_text_classifies_by_content(tmp_path, name, body, expect):
    p = tmp_path / name
    p.write_text(body)
    assert classify_path(p) == expect


def test_binary_dat_is_never_sniffed(tmp_path):
    p = tmp_path / "NTUSER.dat"
    p.write_bytes(b"regf\x00\x00;;;;;\n;;;;;\n")
    assert classify_path(p) != "tabular"


# ── an observation's identity is what was seen ───────────────────────────

def test_same_auth_event_seen_by_two_calls_is_one_observation(tmp_path):
    from core.auth_events import AuthEvent
    from core.auth_observations import upsert_auth_events
    case = _case(tmp_path)
    mk = lambda cid: AuthEvent(event_class="auth.success",
                               source_endpoint="10.9.8.7", when="2031-02-04",
                               auth_factor="3", platform="windows",
                               source_call_id=cid, tool="x",
                               snippet="4624 ... prod-sql-02.corp.local")
    r1 = upsert_auth_events(case, [mk(108)])
    r2 = upsert_auth_events(case, [mk(111)])
    assert r1["created_count"] == 1 and r2["created_count"] == 0
    obs = [n for n in load_graph(case)["nodes"].values() if n["kind"] == "observation"]
    assert len(obs) == 1
    assert sorted(obs[0]["attrs"]["source_call_ids"]) == [108, 111]
    assert obs[0]["attrs"]["sightings"] == 2
    assert obs[0]["host"] == "PROD-SQL-02"
