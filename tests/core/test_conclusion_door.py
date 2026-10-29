"""The conclusion door (ATLAS_CONCLUSION_DOOR): a conclusion
names its basis, states only names its basis states, covers with an absence
only the hosts its bases read, and is never stronger than its weakest
basis. Invented fixtures only (CORP-WS01, CORP-DC01, jane.doe, 203.0.113.x,
dates in 2031)."""
from __future__ import annotations

import json

import pytest

from core import claim_graph as G
from core.execution_log import ExecutionLog


@pytest.fixture
def case(tmp_path, monkeypatch):
    root = tmp_path / "case"
    for d in (".atlas", "analysis", "evidence/disk"):
        (root / d).mkdir(parents=True)
    log = ExecutionLog()
    log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    return root, log


def _call(log, tool="table_table_grep", args=None, out="row"):
    cid = log.record_tool_call(f"<py>:{tool}", True, False, 0, 0, stdout_excerpt=out)
    log.annotate_tool_call(cid, args=json.dumps(args or {"path": "evidence/x.csv"}), mcp_tool=tool)
    return cid


def _claim(root, log, statement, tier="LIKELY", host="", args=None, out="row"):
    call = _call(log, args=args, out=out)
    r = G.upsert_claim_from_finding(root, statement=statement, confidence=tier, host=host,
                                    finding_call_id=call + 100_000, linked_call_id=call,
                                    input_call_ids=[call], analyst_call_ids=[call], fresh=True)
    return r["claim_id"]


def _promote(root, **kw):
    from tools.claim_tools import promote_conclusion
    fn = getattr(promote_conclusion, "fn", promote_conclusion)
    return fn(case_dir=str(root), **kw)


def _node(root, nid):
    return G.load_graph(root)["nodes"][nid]


def test_a_basis_is_required_and_the_tier_is_the_weakest_basis(case):
    root, log = case
    assert "basis_ids is empty" in _promote(root, statement="x happened")["error"]
    c1 = _claim(root, log, "dropper.exe ran on CORP-WS01 at 09:12", "LIKELY")
    c2 = _claim(root, log, "CORP-WS01 connected to 203.0.113.7 at 09:20", "SUSPECTED")
    r = _promote(root, basis_ids=f"{c1},{c2}", confidence="CONFIRMED",
                 statement="dropper.exe ran on CORP-WS01 at 09:12 and the host connected to 203.0.113.7 at 09:20")
    assert r["success"] and r["confidence"] == "SUSPECTED" and r["basis_ids"] == [c1, c2]
    assert f"{c2} is SUSPECTED" in r["note"]
    node = _node(root, r["node_id"])
    assert node["requested_confidence"] == "CONFIRMED" and node["tier_bound"] == {"by": c2, "tier": "SUSPECTED"}


def test_a_name_no_basis_states_is_refused_with_the_claims_that_state_it(case):
    root, log = case
    c1 = _claim(root, log, "dropper.exe ran on CORP-WS01 at 09:12")
    c2 = _claim(root, log, "CORP-WS01 connected to 203.0.113.7 at 09:20")
    stmt = "dropper.exe on CORP-WS01 beaconed to 203.0.113.7"
    r = _promote(root, basis_ids=c1, statement=stmt)
    assert not r["success"] and r["gate"] == "conclusion_basis"
    assert f"203.0.113.7: add {c2} to basis_ids" in r["error"]
    assert r["unbacked"][0]["claims"] == [c2]
    assert _promote(root, basis_ids=f"{c1},{c2}", statement=stmt)["success"]


def test_a_value_no_claim_states_points_at_the_calls_that_show_it(case):
    root, log = case
    c1 = _claim(root, log, "dropper.exe ran on CORP-WS01 at 09:12")
    shown = _call(log, args={"path": "evidence/proxy.csv", "pattern": "files.example.com"},
                  out="2031-01-04 09:30:00,CORP-WS01,GET files.example.com/a.bin")
    r = _promote(root, basis_ids=c1, statement="dropper.exe on CORP-WS01 fetched from files.example.com")
    row = next(u for u in r["unbacked"] if u["value"] == "files.example.com")
    assert row["claims"] == [] and shown in row["calls"] and "record a finding citing" in r["error"]
    r = _promote(root, basis_ids=c1, statement="dropper.exe on CORP-WS01 used 444 sockets")
    assert "no call in the trace shows it: leave it out" in r["error"]


def test_a_claim_without_a_finding_and_an_uncalled_observation_are_no_basis(case):
    root, log = case
    bare = G.add_claim(root, "jane.doe logged on to CORP-WS01", confidence="LIKELY",
                       enforce_validation=False)["node_id"]
    r = _promote(root, basis_ids=bare)
    assert "was not recorded with misc.record_finding" in r["error"]
    cid = _call(log)
    obs = G.add_observation(root, "the time zone of CORP-WS01 is UTC",
                            evidence=[{"artifact": "SYSTEM", "locator": "TimeZoneInformation", "call_id": cid}])
    assert _promote(root, basis_ids=obs["node_id"])["success"]
    loose = G.add_observation(root, "the build of CORP-WS01 is 19045",
                              evidence=[{"artifact": "SOFTWARE", "locator": "CurrentBuild", "call_id": None}])
    assert "no tool call stands behind" in _promote(root, basis_ids=loose["node_id"])["error"]


def test_kept_words_carry_the_tier_and_a_rewrite_is_capped_at_likely(case):
    root, log = case
    c1 = _claim(root, log, "dropper.exe ran on CORP-WS01 at 09:12", "CONFIRMED")
    kept = _promote(root, basis_ids=c1)
    assert kept["confidence"] == "CONFIRMED" and _node(root, kept["node_id"])["kept_words"] is True
    rewritten = _promote(root, basis_ids=c1, confidence="CONFIRMED",
                         statement="On CORP-WS01, dropper.exe ran at 09:12")
    assert rewritten["confidence"] == "LIKELY" and "reason.evaluate_finding" in rewritten["note"]


def test_the_bound_follows_supersession_and_withdrawal(case):
    root, log = case
    c1 = _claim(root, log, "dropper.exe ran on CORP-WS01 at 09:12", "LIKELY")
    n = _promote(root, basis_ids=c1)["node_id"]
    same = _claim(root, log, "dropper.exe ran on CORP-WS01 at 09:12", "SUSPECTED")
    G.supersede(root, c1, same, reason="re-recorded with its citation")
    node = _node(root, n)
    assert node["basis_ids"] == [same] and node["status"] != "needs_review" and node["confidence"] == "SUSPECTED"
    G.supersede(root, same, "", reason="the run can no longer support the dropper execution")
    node = _node(root, n)
    assert node["status"] == "needs_review" and node["review_reason"] == f"basis {same} withdrawn"
    assert node["confidence"] == "UNCONFIRMED"


def test_a_kept_words_basis_revised_in_other_words_puts_the_conclusion_under_review(case):
    root, log = case
    c1 = _claim(root, log, "dropper.exe ran on CORP-WS01 at 09:12")
    n = _promote(root, basis_ids=c1)["node_id"]
    c2 = _claim(root, log, "dropper.exe ran on CORP-WS01 at 09:14")
    G.supersede(root, c1, c2, reason="the time was misread")
    node = _node(root, n)
    assert node["status"] == "needs_review" and node["review_reason"] == f"basis {c1} revised"


def test_a_kept_words_conclusion_reports_its_basis_status_and_folds_it(case):
    root, log = case
    c1 = _claim(root, log, "dropper.exe ran on CORP-WS01 at 09:12")
    G.set_citation_status(root, c1, "located", [7])
    n = _promote(root, basis_ids=c1)["node_id"]
    assert _node(root, n)["citation_status"] == "located"
    from core.finding_index import ensure_finding_ids, nodes_for_report
    ensure_finding_ids(root)
    ids = [x["id"] for x in nodes_for_report(root)]
    assert n in ids and c1 not in ids
    c2 = _claim(root, log, "CORP-WS01 connected to 203.0.113.7 at 09:20")
    _promote(root, basis_ids=c2, statement="CORP-WS01 reached 203.0.113.7 at 09:20")
    ensure_finding_ids(root)
    assert c2 in [x["id"] for x in nodes_for_report(root)]


def test_an_absence_covers_only_the_hosts_its_bases_read(case):
    root, log = case
    hosts = ("CORP-DC01", "CORP-WS01", "CORP-WS02")
    for h in hosts:
        (root / "evidence" / "disk" / f"{h.lower()}.raw").write_bytes(b"\0")
    (root / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": h, "path": f"evidence/disk/{h.lower()}.raw"} for h in hosts]}), encoding="utf-8")
    c1 = _claim(root, log, "no log clearing on CORP-DC01", host="CORP-DC01",
                args={"image": "evidence/disk/corp-dc01.raw", "pattern": "1102"}, out="0 rows")
    r = _promote(root, basis_ids=c1, statement="No log clearing was found")
    assert not r["success"] and r["gate"] == "conclusion_scope" and "covers all 3 hosts" in r["error"]
    assert "CORP-DC01" in r["error"]
    assert _promote(root, basis_ids=c1, statement="No log clearing was found on CORP-DC01")["success"]


def test_revision_supersedes_the_old_conclusion(case):
    root, log = case
    c1 = _claim(root, log, "dropper.exe ran on CORP-WS01 at 09:12")
    n1 = _promote(root, basis_ids=c1)["node_id"]
    n2 = _promote(root, supersedes=n1, statement="dropper.exe ran on CORP-WS01")["node_id"]
    assert _node(root, n1)["status"] == "superseded" and _node(root, n2)["basis_ids"] == [c1]
    n3 = _promote(root, claim_id=n2, statement="dropper.exe ran on CORP-WS01 at 09:12")["node_id"]
    assert _node(root, n2)["superseded_by"] == n3


def test_a_conclusion_changes_only_through_the_door(case):
    root, log = case
    from tools.claim_tools import supersede
    sup = getattr(supersede, "fn", supersede)
    c1 = _claim(root, log, "dropper.exe ran on CORP-WS01 at 09:12")
    n = _promote(root, basis_ids=c1)["node_id"]
    c2 = _claim(root, log, "dropper.exe ran on CORP-WS01 at 09:13")
    assert "revise it with claim.promote_conclusion(supersedes=" in sup(n, c2, case_dir=str(root))["error"]
    assert "does not replace its own basis" in sup(c1, n, case_dir=str(root))["error"]
    from types import SimpleNamespace
    from tools._gates import supersedes_target
    ctx = SimpleNamespace(supersedes=n, log=log, host="", description="d", confidence="LIKELY")
    assert f"{n} is a conclusion: revise it with claim.promote_conclusion(supersedes={n})" in \
        supersedes_target.check(ctx)["error"]


def test_a_legacy_promoted_conclusion_is_bounded_on_load(case):
    root, log = case
    c1 = _claim(root, log, "dropper.exe ran on CORP-WS01 at 09:12", "SUSPECTED")
    graph = G.load_graph(root)
    graph["nodes"]["N0099"] = {"id": "N0099", "kind": "conclusion", "status": "new", "confidence": "CONFIRMED",
                               "statement": "dropper.exe ran on CORP-WS01 at 09:12", "promoted_from_claim_id": c1}
    (root / ".atlas" / "claim_graph.json").write_text(json.dumps(graph), encoding="utf-8")
    node = _node(root, "N0099")
    assert node["basis_ids"] == [c1] and node["confidence"] == "SUSPECTED" and node["requested_confidence"] == "CONFIRMED"


def test_the_switch_off_promotes_as_before(case, monkeypatch):
    root, log = case
    monkeypatch.setenv("ATLAS_CONCLUSION_DOOR", "0")
    c1 = _claim(root, log, "dropper.exe ran on CORP-WS01 at 09:12", "SUSPECTED")
    r = _promote(root, claim_id=c1, statement="something else on 203.0.113.250", confidence="CONFIRMED")
    assert r["success"] and _node(root, r["node_id"])["confidence"] == "CONFIRMED"


def test_a_rewritten_universal_meets_the_statement_gates_and_a_prescription_does_not(case):
    root, log = case
    cut = log.record_tool_call("<py>:table_table_grep", True, True, 0, 0,
                               stdout_excerpt="2031-01-04 09:12 jane.doe logon type 10 CORP-WS01")
    log.annotate_tool_call(cut, args=json.dumps({"path": "evidence/logons.csv", "pattern": "jane.doe"}),
                           mcp_tool="table_table_grep")
    c1 = G.upsert_claim_from_finding(root, statement="jane.doe logged on interactively to CORP-WS01",
                                     confidence="LIKELY", finding_call_id=cut + 100_000, linked_call_id=cut,
                                     input_call_ids=[cut], analyst_call_ids=[cut], fresh=True)["claim_id"]
    r = _promote(root, basis_ids=c1, statement="every logon of jane.doe to CORP-WS01 was interactive")
    assert not r["success"] and r["gate"] == "universal_from_truncated"
    ok = _promote(root, basis_ids=c1, statement="jane.doe must reset every password on CORP-WS01")
    assert ok["success"], ok


# ── section 7: the name check's lexicon and variants ─────────────────────

def _hosts(root, hosts):
    for h in hosts:
        (root / "evidence" / "disk" / f"{h.lower()}.raw").write_bytes(b"\0")
    (root / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": h, "path": f"evidence/disk/{h.lower()}.raw"} for h in hosts]}), encoding="utf-8")


def test_a_bare_account_from_another_belief_is_refused(case):
    root, log = case
    base = _claim(root, log, "dropper.exe ran on CORP-WS01")
    other = _claim(root, log, "EXAMPLE\\jdoe logged on to CORP-WS01")
    r = _promote(root, basis_ids=base, statement="jdoe ran dropper.exe on CORP-WS01")
    assert not r["success"] and f"jdoe: add {other} to basis_ids" in r["error"]
    assert _promote(root, basis_ids=f"{base},{other}", statement="jdoe ran dropper.exe on CORP-WS01")["success"]


def test_a_raw_date_and_time_with_seconds_is_stated_by_its_basis(case):
    root, log = case
    c1 = _claim(root, log, "dropper.exe ran on CORP-WS01 at 2031-01-04 09:12:33")
    assert _promote(root, basis_ids=c1, statement="On 2031-01-04 09:12:33 dropper.exe ran on CORP-WS01")["success"]


def test_a_host_or_a_minute_only_the_conclusion_names_is_refused_as_written(case):
    root, log = case
    _hosts(root, ("CORP-WS01", "CORP-WS02"))
    c1 = _claim(root, log, "dropper.exe ran on CORP-WS01 at 2031-01-04 09:12:33")
    r = _promote(root, basis_ids=c1, statement="dropper.exe ran on CORP-WS02 at 2031-01-04 09:12:33")
    assert not r["success"] and "names CORP-WS02," in r["error"]
    r = _promote(root, basis_ids=c1, statement="dropper.exe ran on CORP-WS01 at 09:47")
    assert not r["success"] and [u["value"] for u in r["unbacked"]] == ["09:47"]


def test_the_variants_of_a_name(case):
    root, log = case
    p1 = _claim(root, log, "dropper.exe ran from C:\\Users\\Public\\dropper.exe on CORP-WS01")
    assert "C:\\Temp\\dropper.exe" in _promote(
        root, basis_ids=p1, statement="dropper.exe ran from C:\\Temp\\dropper.exe on CORP-WS01")["error"]
    assert _promote(root, basis_ids=p1,
                    statement="dropper.exe ran from c:/users/public/DROPPER.EXE on CORP-WS01")["success"]
    ip = _claim(root, log, "CORP-WS01 connected to 203.0.113.7")
    r = _promote(root, basis_ids=ip, statement="CORP-WS01 connected to 203.0.113.8")
    assert [u["value"] for u in r["unbacked"]] == ["203.0.113.8"]
    cid = _call(log)
    ev = G.add_observation(root, "a service was installed on CORP-WS01", evidence=[
        {"artifact": "System.evtx", "locator": "service svc-update installed", "call_id": cid}])["node_id"]
    assert _promote(root, basis_ids=ev, statement="the service svc-update was installed on CORP-WS01")["success"]


# ── section 7: the statement gates and the cap ───────────────────────────

def test_an_external_name_is_refused_at_likely_and_accepted_at_a_suspected_bound(case):
    root, log = case
    likely = _claim(root, log, "dropper.exe on CORP-WS01 beaconed every 60 seconds", "LIKELY")
    r = _promote(root, basis_ids=likely, confidence="LIKELY",
                 statement="dropper.exe on CORP-WS01 is a Cobalt Strike beacon")
    assert not r["success"] and r["gate"] == "attribution"
    weak = _claim(root, log, "dropper.exe on CORP-WS01 beaconed every 30 seconds", "SUSPECTED")
    r = _promote(root, basis_ids=weak, statement="dropper.exe on CORP-WS01 is a Cobalt Strike beacon")
    assert r["success"] and r["confidence"] == "SUSPECTED"


def test_an_observation_basis_in_the_same_words_takes_the_cap(case):
    root, log = case
    cid = _call(log)
    obs = G.add_observation(root, "the time zone of CORP-WS01 is UTC", confidence="CONFIRMED",
                            evidence=[{"artifact": "SYSTEM", "locator": "TimeZoneInformation", "call_id": cid}])
    r = _promote(root, basis_ids=obs["node_id"], confidence="CONFIRMED", statement="the time zone of CORP-WS01 is UTC")
    assert r["success"] and r["confidence"] == "LIKELY" and "reason.evaluate_finding" in r["note"]


def test_a_quote_from_a_call_500_entries_back_is_grounded(case):
    root, log = case
    c1 = _claim(root, log, "dropper.exe on CORP-WS01 ran whoami /all", out="cmd.exe /c whoami /all")
    for _ in range(500):
        _call(log, args={"path": "evidence/other.csv"}, out="noise")
    assert _promote(root, basis_ids=c1, statement='dropper.exe on CORP-WS01 ran "whoami /all"')["success"]
    assert not _promote(root, basis_ids=c1, statement='dropper.exe on CORP-WS01 ran "whoami /all /fo list"')["success"]


# ── section 7: absence scope over an estate ──────────────────────────────

def test_an_estate_absence_needs_every_host_read(case):
    root, log = case
    hosts = [f"CORP-WS0{i}" for i in range(1, 6)]
    _hosts(root, hosts)
    ids = [_claim(root, log, f"no log clearing on {h}", host=h, out="0 rows",
                  args={"image": f"evidence/disk/{h.lower()}.raw", "pattern": "1102"}) for h in hosts]
    r = _promote(root, basis_ids=",".join(ids[:2]), statement="No log clearing was found")
    assert not r["success"] and "covers all 5 hosts" in r["error"]
    assert "its basis read 2: CORP-WS01, CORP-WS02" in r["error"]
    assert _promote(root, basis_ids=",".join(ids), statement="No log clearing was found")["success"]


def test_a_conclusion_basis_reads_through_its_own_bases(case):
    root, log = case
    _hosts(root, ("CORP-DC01", "CORP-WS01"))
    c1 = _claim(root, log, "no log clearing on CORP-DC01", host="CORP-DC01", out="0 rows",
                args={"image": "evidence/disk/corp-dc01.raw", "pattern": "1102"})
    n1 = _promote(root, basis_ids=c1, statement="No log clearing was found on CORP-DC01")["node_id"]
    assert _promote(root, basis_ids=n1, statement="No log clearing was found on CORP-DC01 at all")["success"]


# ── section 7: the bound over a chain and the task links ─────────────────

def test_a_chain_of_conclusions_is_bounded_on_one_load(case):
    root, log = case
    c1 = _claim(root, log, "dropper.exe ran on CORP-WS01 at 09:12", "SUSPECTED")
    graph = G.load_graph(root)
    # The dependent conclusion comes first in node order.
    graph["nodes"] = {"N0098": {"id": "N0098", "kind": "conclusion", "status": "new", "confidence": "CONFIRMED",
                                "statement": "s", "basis_ids": ["N0099"], "requested_confidence": "CONFIRMED"},
                      **graph["nodes"],
                      "N0099": {"id": "N0099", "kind": "conclusion", "status": "new", "confidence": "CONFIRMED",
                                "statement": "s", "basis_ids": [c1], "requested_confidence": "CONFIRMED"}}
    (root / ".atlas" / "claim_graph.json").write_text(json.dumps(graph), encoding="utf-8")
    assert _node(root, "N0098")["confidence"] == "SUSPECTED"


def test_a_revision_carries_the_task_links(case):
    root, log = case
    from core.investigation_tasks import load_tasks, reconcile_case_md, update_task
    (root / "CASE.md").write_text("## Investigation Requests\n\n- Execution: whether dropper.exe ran\n",
                                  encoding="utf-8")
    tid = reconcile_case_md(root, persist=True)["added"][0]
    c1 = _claim(root, log, "dropper.exe ran on CORP-WS01 at 09:12")
    n1 = _promote(root, basis_ids=c1)["node_id"]
    assert update_task(root, tid, related_claim_ids=[n1])["success"]
    n2 = _promote(root, supersedes=n1, statement="dropper.exe ran on CORP-WS01")["node_id"]
    task = {t["id"]: t for t in load_tasks(root)["tasks"]}[tid]
    assert n2 in task["related_claim_ids"]
