"""A close is not trapped by what the recognisers cannot read: parts may
arrive as JSON text, a belief id given as a limitation's basis is read as
the link, a belief the analyst links to a part answers it when it carries
what the part asks about (marked, and shown as such in the report), and a
yes/no part is answered by what it asks about, never by its verb or by the
request's topic alone."""
import json

import pytest

from core import claim_graph as cg
from core import request_parts as rp
from core.investigation_tasks import PARTS_EXAMPLE, load_tasks, reconcile_case_md, update_task


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "C"
    (d / ".atlas").mkdir(parents=True)
    (d / "CASE.md").write_text("**Case ID:** C\n\n## Investigation Requests\n"
                               "- Chat client — the chat user settings and the logged channels.\n",
                               encoding="utf-8")
    reconcile_case_md(d)
    return d


def _claim(case, text, confidence="LIKELY"):
    r = cg.add_claim(case, statement=text, confidence=confidence, host="WS01")
    assert r["success"], r
    return r["node_id"]


def _task(case):
    return load_tasks(case)["tasks"][0]


def _node(nid, statement, kind="claim"):
    return {"id": nid, "kind": kind, "status": "new", "statement": statement, "host": "", "confidence": "LIKELY"}


class TestForgivingArguments:
    def test_parts_as_json_text_close_like_the_object(self, case):
        from tools.misc import update_investigation_task
        c = _claim(case, "The chat client's settings file names the nick zed, the alternate nick zed2 and the ident zz.")
        tid = _task(case)["id"]
        r = update_investigation_task(tid, case_dir=str(case), parts=json.dumps({"p1": {"claim_ids": [c]}}))
        assert r["success"], r
        p1 = next(p for p in r["task"]["parts"] if p["id"] == "p1")
        assert p1["status"] == "answered" and p1["bound_by"] == "analyst"
        bad = update_investigation_task(tid, case_dir=str(case), parts="p1 is answered by the settings claim")
        assert not bad["success"] and PARTS_EXAMPLE in bad["error"]

    def test_a_belief_id_in_the_basis_is_read_as_the_link(self, case):
        c = _claim(case, "The chat client's settings file names the nick zed and the ident zz.")
        tid = _task(case)["id"]
        r = update_task(case, tid, parts={"p1": {"limitation": {"basis": c, "reason": "see the settings claim"}}})
        assert r["success"], r
        assert next(p for p in r["task"]["parts"] if p["id"] == "p1")["status"] == "answered"
        assert any("read as the part's link" in n for n in r["notes"])
        bad = update_task(case, tid, parts={"p2": {"limitation": {"basis": "C9999", "reason": "an id that is not a belief"}}})
        assert not bad["success"] and bad["gate"] == "task_part_limitation"


class TestTheAnalystsLink:
    def test_a_value_the_binder_cannot_read_is_answered_by_the_link_and_marked(self, case):
        c = _claim(case, "The chat client's user settings: nick=zed, ident=zz, full name Some One.")
        tid = _task(case)["id"]
        r = update_task(case, tid, parts={"p1": {"claim_ids": [c]}})
        p1 = next(p for p in r["task"]["parts"] if p["id"] == "p1")
        assert p1["status"] == "answered" and p1["value"] == "" and p1["bound_by"] == "analyst"
        assert any("analyst link, no typed value" in line for line in r["parts"])

    def test_a_link_to_a_belief_about_something_else_or_an_absence_is_refused(self, case, monkeypatch):
        monkeypatch.setenv("ATLAS_PART_GATE_STRUCTURAL", "0")   # the lexical gate's path
        other = _claim(case, "The notebook's shell history shows a network scanner run at logon.")
        absent = _claim(case, "No chat user settings were found in the profile.")
        tid = _task(case)["id"]
        for cid in (other, absent):
            r = update_task(case, tid, parts={"p1": {"claim_ids": [cid]}})
            assert not r["success"] and r["gate"] == "task_part_unsupported"
            assert "chat, settings" in r["error"] and PARTS_EXAMPLE in r["error"]

    def test_a_successor_that_states_a_value_replaces_the_link(self, case):
        t = {"text": "Accounts — the local accounts.", "parts": rp.split_request("Accounts — the local accounts.")}
        nodes = {"C1": _node("C1", "The local accounts list shows three entries of the kind a workstation keeps.")}
        rp.assign(t, nodes, ["C1"], explicit={"p1": ["C1"]}, lenient=True)
        assert t["parts"][0]["bound_by"] == "analyst"
        nodes["C2"] = _node("C2", "The local accounts are CORP\\alice and CORP\\bob.")
        rp.carry(t, "C1", "C2", nodes)
        assert t["parts"][0]["status"] == "answered" and "bound_by" not in t["parts"][0] and t["parts"][0]["value"]


class TestYesNoParts:
    Q = "Malware — whether the machine carries viruses."

    def _t(self, text=Q):
        return {"text": text, "parts": rp.split_request(text)}

    @pytest.mark.parametrize("statement,answers", [
        ("The notebook carries a wireless-hacking toolset of scanners and sniffers.", False),   # the verb alone
        ("No anti-virus software is installed on the notebook.", False),                          # tooling, not a member
        ("ClamAV detected Win.Trojan.Example-1 in helper.dll on the notebook.", True),             # a member of the class
        ("A scan of the whole image found no virus.", True),                                       # the word itself, a "no"
        ("No anti-virus product is installed: a search for virus, antivirus returned 0 hits.", False),  # a search term
    ])
    def test_a_yes_no_part_is_answered_by_what_it_asks_about(self, statement, answers):
        t = self._t()
        done = rp.assign(t, {"C1": _node("C1", statement)}, ["C1"], lenient=True)
        assert (done == ["p1"]) is answers

    def test_a_named_belief_is_read_whole(self):
        t = self._t()
        scan = _node("C1", "The scanner read 12,000 files of the image: no virus or other malware was detected.")
        assert rp.assign(t, {"C1": scan}, ["C1"], lenient=True) == []                     # not in its headline
        assert rp.assign(t, {"C1": scan}, ["C1"], explicit={"p1": ["C1"]}, lenient=True) == ["p1"]

    def test_a_part_with_no_words_of_its_own_reads_the_request(self):
        t = {"text": "Data — was anything uploaded? if so", "parts": [
            rp._part("p1", "if so", "yes_no", "value", "question")]}
        done = rp.assign(t, {"C1": _node("C1", "Data was uploaded over FTP to an outside server.")}, ["C1"], lenient=True)
        assert done == ["p1"]


class TestVerdictAnswers:
    """The only part of a yes/no request is answered by a belief tied to it
    that opens with a verdict, in other words than the question's; a
    determiner "No" is no verdict, and a task-level link cannot say which
    of several parts a verdict answers."""
    ONE = "Did data exfiltration occur?"
    YES = "Yes — data left via HTTPS to a rented virtual server."

    def _t(self, text):
        return {"text": text, "parts": rp.split_request(text)}

    def test_a_verdict_linked_to_the_only_part_answers_it(self):
        assert rp.assign(self._t(self.ONE), {"C1": _node("C1", self.YES)}, ["C1"], lenient=True) == ["p1"]

    def test_a_verdict_named_for_the_only_part_answers_it(self):
        done = rp.assign(self._t(self.ONE), {"C1": _node("C1", self.YES)}, ["C1"],
                         explicit={"p1": ["C1"]}, lenient=True)
        assert done == ["p1"]

    def test_a_determiner_no_is_no_verdict(self):
        t = self._t("Malware — whether the machine carries viruses.")
        node = _node("C1", "No anti-virus software is installed on the notebook.")
        assert rp.assign(t, {"C1": node}, ["C1"], lenient=True) == []

    def test_a_task_level_verdict_does_not_pick_one_of_several_parts(self):
        t = self._t("Exfiltration — whether data left the network, and which accounts were used.")
        yes_no = [p["id"] for p in t["parts"] if p["type"] == "yes_no"]
        assert len(t["parts"]) > 1 and yes_no
        done = rp.assign(t, {"C1": _node("C1", "Yes, over HTTPS to a rented virtual server.")}, ["C1"],
                         lenient=True)
        assert not set(done) & set(yes_no)


def test_a_one_part_answer_taken_on_a_link_is_itemised_in_the_report():
    from core.report_assemble import _part_lines
    task = {"parts": [{"id": "p1", "text": "the chat user settings", "type": "account", "status": "answered",
                       "claim_ids": ["C1"], "value": "", "bound_by": "analyst"}]}
    lines = _part_lines(task, {"C1": "F-004"}, "en")
    assert any("answered through the linked finding" in x and "F-004" in x for x in lines)
    task["parts"][0].pop("bound_by")
    assert _part_lines(task, {"C1": "F-004"}, "en") == []


def test_a_belief_stating_two_values_of_the_kind_is_refused_with_both_until_one_is_typed(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_PART_GATE_STRUCTURAL", "0")   # the lexical gate's path
    d = tmp_path / "N"
    (d / ".atlas").mkdir(parents=True)
    (d / "CASE.md").write_text("**Case ID:** N\n\n## Investigation Requests\n- Network — the C2 IP.\n",
                               encoding="utf-8")
    reconcile_case_md(d)
    tid = load_tasks(d)["tasks"][0]["id"]
    cid = _claim(d, "Beacon traffic left 10.0.0.5 for 203.0.113.9 every 60 s.")
    r = update_task(d, tid, parts={"p1": {"claim_ids": [cid]}})
    assert not r["success"] and r["gate"] == "task_part_unsupported"
    assert "2 ip values (10.0.0.5, 203.0.113.9)" in r["error"] and "claim.add_indicators" in r["error"]
    cg.set_claim_indicators(d, cid, [{"type": "ip", "value": "203.0.113.9", "side": "attacker"}])
    r = update_task(d, tid, parts={"p1": {"claim_ids": [cid]}})
    assert r["success"], r
    assert next(p for p in r["task"]["parts"] if p["id"] == "p1")["value"] == "203.0.113.9"


def test_a_belief_typing_every_value_it_states_is_not_told_to_type_one(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_PART_GATE_STRUCTURAL", "0")   # the lexical gate's path
    d = tmp_path / "N"
    (d / ".atlas").mkdir(parents=True)
    (d / "CASE.md").write_text("**Case ID:** N\n\n## Investigation Requests\n- Network — the C2 IP.\n",
                               encoding="utf-8")
    reconcile_case_md(d)
    tid = load_tasks(d)["tasks"][0]["id"]
    cid = _claim(d, "Beacon traffic left 10.0.0.5 for 203.0.113.9 every 60 s.")
    cg.set_claim_indicators(d, cid, [{"type": "ip", "value": "10.0.0.5", "side": "victim"},
                                     {"type": "ip", "value": "203.0.113.9", "side": "attacker"}])
    r = update_task(d, tid, parts={"p1": {"claim_ids": [cid]}})
    assert not r["success"] and "already typed" in r["error"] and "claim.add_indicators" not in r["error"]


def _yes_no_case(tmp_path):
    d = tmp_path / "Y"
    (d / ".atlas").mkdir(parents=True)
    (d / "CASE.md").write_text("**Case ID:** Y\n\n## Investigation Requests\n"
                               "- Is there evidence that the event logs were cleared on CORP-WS01?\n"
                               "- Which IP address did the attacker connect from?\n", encoding="utf-8")
    reconcile_case_md(d)
    return d, [t["id"] for t in load_tasks(d)["tasks"]]


def test_the_structural_gate_accepts_a_stating_belief_whatever_its_words(tmp_path):
    d, (yes_no, how) = _yes_no_case(tmp_path)
    c = cg.add_claim(d, statement="The Security log of CORP-WS01 was cleared at 2031-01-04 09:12 by jane.doe.",
                     confidence="LIKELY", host="CORP-WS01")["node_id"]
    r = update_task(d, yes_no, parts={"p1": {"claim_ids": [c]}})
    assert r["success"], r
    p1 = r["task"]["parts"][0]
    assert p1["status"] == "answered" and p1["closed_by"] == "analyst" and p1["bound_by"] == "analyst"
    v = cg.add_claim(d, statement="jane.doe logged on over RDP with a phished password.",
                     confidence="LIKELY", host="CORP-WS01")["node_id"]
    assert update_task(d, how, parts={"p1": {"claim_ids": [v]}})["success"]     # no address: the reviewer judges


def test_a_gap_is_no_answer_and_an_absence_answers_only_yes_no(tmp_path):
    d, (yes_no, how) = _yes_no_case(tmp_path)
    gap = cg.add_claim(d, statement="Whether the logs were cleared could not be determined: the log is unreadable.",
                       confidence="SUSPECTED", host="CORP-WS01")["node_id"]
    absent = cg.add_claim(d, statement="No log clearing was found on CORP-WS01.",
                          confidence="LIKELY", host="CORP-WS01")["node_id"]
    r = update_task(d, yes_no, parts={"p1": {"claim_ids": [gap]}})
    assert not r["success"] and r["gate"] == "task_part_unsupported"
    assert update_task(d, yes_no, parts={"p1": {"claim_ids": [absent]}})["success"]
    r = update_task(d, how, parts={"p1": {"claim_ids": [absent]}})
    assert not r["success"] and "an absence" in r["error"]


def test_under_the_structural_gate_only_the_beliefs_a_call_names_answer_a_part(tmp_path):
    """A stored or record-time link answers no part on an update; a close of
    a one-part task naming a belief binds it to that part by structure."""
    from core.investigation_tasks import link_claim_to_tasks
    d, (yes_no, how) = _yes_no_case(tmp_path)
    text = "The Security log of CORP-WS01 was cleared at 2031-01-04 09:12 by jane.doe."
    c = cg.add_claim(d, statement=text, confidence="LIKELY", host="CORP-WS01")["node_id"]
    link_claim_to_tasks(d, c, statement=text, host="CORP-WS01")
    r = update_task(d, yes_no, status="answered")
    assert not r["success"] and r["gate"] == "task_parts_open"
    r = update_task(d, yes_no, status="answered", related_claim_ids=[c])
    assert r["success"], r
    p1 = r["task"]["parts"][0]
    assert p1["status"] == "answered" and p1["bound_by"] == "analyst" and p1["claim_ids"] == [c]


def _hosts_case(tmp_path):
    d = tmp_path / "H"
    (d / ".atlas").mkdir(parents=True)
    (d / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-WS01", "path": "ws01.E01"}, {"label": "CORP-WS02", "path": "ws02.E01"}]}))
    (d / "CASE.md").write_text(
        "**Case ID:** H\n\n## Investigation Requests\n"
        "- Was any host reached over RDP?\n- Was CORP-WS01 reached over RDP?\n", encoding="utf-8")
    reconcile_case_md(d)
    return d, [t["id"] for t in load_tasks(d)["tasks"]]


def test_an_absence_answers_a_yes_no_part_only_over_the_hosts_it_asks_about(tmp_path, monkeypatch):
    from core.conclusion_door import _case_hosts
    d, (estate, one) = _hosts_case(tmp_path)
    assert _case_hosts(d) == ["CORP-WS01", "CORP-WS02"]
    ws01 = cg.add_claim(d, statement="No RDP logon was found on CORP-WS01.", confidence="LIKELY",
                        host="CORP-WS01")["node_id"]
    r = update_task(d, estate, parts={"p1": {"claim_ids": [ws01]}})
    assert not r["success"] and "CORP-WS02" in r["error"] and "fewer hosts" in r["error"]
    assert update_task(d, one, parts={"p1": {"claim_ids": [ws01]}})["success"]
    both = cg.add_claim(d, statement="No RDP logon was found on CORP-WS01 or CORP-WS02.",
                        confidence="LIKELY", host="")["node_id"]
    assert update_task(d, estate, parts={"p1": {"claim_ids": [both]}})["success"]
