"""Parts of a request: the split, the status a task takes from them, and
how a part is answered, limited or reopened."""
from __future__ import annotations

import pytest

from core import answer_values as av
from core import request_parts as rp


def _node(nid, statement, kind="claim", status="new", host=""):
    return {"id": nid, "kind": kind, "status": status, "statement": statement, "host": host,
            "confidence": "LIKELY"}


class TestSplit:
    def test_a_baseline_request_lists_its_parts_with_their_kinds(self):
        parts = rp.split_request("Device and system baseline — image integrity, operating system, install date, "
                                 "timezone, registered owner, computer name, primary domain, last shutdown, accounts.")
        assert [(p["text"], p["type"]) for p in parts] == [
            ("image integrity", "name"), ("operating system", "os"), ("install date", "datetime"),
            ("timezone", "zone"), ("registered owner", "name"), ("computer name", "host"),
            ("primary domain", "domain"), ("last shutdown", "datetime"), ("accounts", "account")]
        assert all(p["kind"] == "value" and p["status"] == "open" for p in parts)

    def test_conjunctions_split_single_words_in_a_list_and_before_a_determiner(self):
        parts = rp.split_request("Network identity — installed NICs, IP and MAC, and which card was in use during the setup.")
        assert [p["text"] for p in parts] == ["installed NICs", "IP", "MAC", "which card was in use during the setup"]
        assert [p["type"] for p in parts][1:3] == ["ip", "mac"]
        parts = rp.split_request("Network — the delivery IP and the C2 IP.")
        assert [(p["text"], p["type"]) for p in parts] == [("the delivery IP", "ip"), ("the C2 IP", "ip")]

    def test_a_relation_request_is_one_relation_part(self):
        parts = rp.split_request("Cross-evidence link — prove the connection between USB content and network traffic.")
        assert len(parts) == 1 and parts[0]["kind"] == "relation" and parts[0]["type"] == "relation"

    def test_guidance_is_dropped_and_a_parenthesised_list_is_opened(self):
        parts = rp.split_request("Baseline — both operating systems; the server's local time (beware: the VM clocks "
                                 "are set one hour off — a config quirk, not timestomping).")
        assert [p["text"] for p in parts] == ["both operating systems", "the server's local time"]
        parts = rp.split_request("Intent — locate and characterise the planning material (manifesto, plan documents, "
                                 "presentation) and the web-search history that shows premeditation.")
        assert [p["text"] for p in parts][:4] == ["the planning material", "manifesto", "plan documents", "presentation"]
        assert parts[-1]["text"].startswith("the web-search history") and parts[-1]["type"] == "list"

    def test_children_are_the_parts_and_an_umbrella_is_one_narrative_part(self):
        parts = rp.split_request("Who used it — main and last user.", ["the account", "the artefact that binds it"])
        assert [p["text"] for p in parts] == ["the account", "the artefact that binds it"]
        parts = rp.split_request("What happened on the hosts?")
        assert len(parts) == 1 and parts[0]["kind"] == "umbrella" and parts[0]["type"] == "narrative"

    def test_a_question_word_types_the_part(self):
        parts = rp.split_request("Lateral movement — access to the desktop, when and with which credentials.")
        assert [(p["text"], p["type"]) for p in parts] == [
            ("access to the desktop", "name"), ("when", "datetime"), ("with which credentials", "account")]
        assert rp.split_request("Malware — whether the machine carries viruses.")[0]["type"] == "yes_no"

    def test_parts_keep_their_status_across_a_re_split(self):
        task = {"text": "Network — the delivery IP and the C2 IP.", "status": "open"}
        assert rp.ensure_parts(task)
        task["parts"][0]["status"] = "answered"; task["parts"][0]["value"] = "203.0.113.10"
        assert not rp.ensure_parts(task)
        task["text"] = "Network — the delivery IP and the C2 IP, and the beacon interval."
        assert rp.ensure_parts(task)
        assert task["parts"][0]["status"] == "answered" and task["parts"][0]["value"] == "203.0.113.10"
        assert task["parts"][2]["status"] == "open"


class TestStatus:
    def _task(self, statuses, bases=None):
        parts = []
        for i, st in enumerate(statuses, 1):
            p = {"id": f"p{i}", "text": f"part {i}", "type": "name", "kind": "value", "status": st,
                 "claim_ids": [], "value": "", "limitation": {}}
            if st == "limited":
                p["limitation"] = {"basis": (bases or {}).get(i, "examined"), "reason": "x" * 20, "call_ids": []}
            parts.append(p)
        return {"text": "q", "status": "open", "related_claim_ids": [], "parts": parts}

    def test_the_rule_is_total(self):
        assert rp.derive_status(self._task(["answered", "answered"])) == "answered"
        assert rp.derive_status(self._task(["answered", "limited"])) == "answered"
        assert rp.derive_status(self._task(["limited", "limited"])) == "blocked_missing_evidence"
        assert rp.derive_status(self._task(["limited", "limited"], {1: "absent", 2: "examined"})) == "blocked_missing_evidence"
        assert rp.derive_status(self._task(["answered", "open"])) == "partial"
        assert rp.derive_status(self._task(["limited", "open"])) == "partial"
        assert rp.derive_status(self._task(["open", "open"])) == "open"
        t = self._task(["open"]); t["related_claim_ids"] = ["C1"]
        assert rp.derive_status(t) == "in_progress"

    def test_markers_and_partless_tasks_keep_their_status(self):
        t = self._task(["answered"]); t["status"] = "reopened"
        assert rp.derive_status(t) == "reopened" and rp.derive_status(t, keep_markers=False) == "answered"
        t["status"] = "dropped"
        assert rp.derive_status(t, keep_markers=False) == "dropped"
        assert rp.derive_status({"text": "q", "status": "partial"}) == "partial"


class TestAssign:
    NET = _node("N1", "Network: delivery IP is 194.61.24.102 (external, attacker host 'attacker-vm'); C2 IP is 10.90.90.90 (internal).", kind="conclusion")

    def _task(self, text):
        t = {"text": text, "status": "open", "related_claim_ids": []}
        rp.ensure_parts(t)
        return t

    def test_two_parts_of_one_kind_take_their_own_values(self):
        t = self._task("Network — the delivery IP and the C2 IP.")
        assert rp.assign(t, {"N1": self.NET}, ["N1"]) == ["p1", "p2"]
        assert [p["value"] for p in t["parts"]] == ["194.61.24.102", "10.90.90.90"]
        assert rp.derive_status(t) == "answered"

    def test_a_value_of_the_right_kind_in_the_wrong_clause_does_not_answer(self):
        t = self._task("Device and system baseline — install date, timezone.")
        acq = _node("C1", "Device and system baseline: the seized evidence is an EnCase image. Acquired 2004-09-20 10:00 UTC by the examiner.")
        assert rp.assign(t, {"C1": acq}, ["C1"]) == []
        inst = _node("C2", "Windows XP was installed on 2004-08-19 22:48:27 UTC (SOFTWARE InstallDate).")
        assert rp.assign(t, {"C1": acq, "C2": inst}, ["C1", "C2"]) == ["p1"]
        assert t["parts"][0]["value"] == "2004-08-19 22:48:27 UTC" and t["parts"][1]["status"] == "open"

    def test_observations_answer_and_gaps_and_absences_do_not(self):
        t = self._task("Baseline — timezone.")
        obs = _node("O1", "The time zone of the notebook is Central Standard Time (SYSTEM TimeZoneInformation).", kind="observation")
        gap = _node("C9", "Absence hypothesis: the timezone was never examined, 3 unexamined categories.")
        assert rp.assign(t, {"C9": gap}, ["C9"]) == []
        assert rp.assign(t, {"O1": obs}, ["O1"]) == ["p1"]

    def test_lexical_parts_close_only_on_the_analysts_update(self):
        t = self._task("Malware — whether the machine carries viruses.")
        det = _node("C3", "ClamAV detected Win.Trojan.Cain-9 in Abel.dll on the notebook.")
        assert rp.assign(t, {"C3": det}, ["C3"]) == []
        assert rp.assign(t, {"C3": det}, ["C3"], lenient=True) == ["p1"]

    def test_a_reading_never_closes_a_lexical_part(self):
        t = self._task("Malware — whether the machine carries viruses.")
        text = "ClamAV detected Win.Trojan.Cain-9 in Abel.dll on the notebook."
        obs = _node("O3", text, kind="observation")
        det = _node("C3", text)
        assert rp.assign(t, {"O3": obs}, ["O3"], lenient=True) == []
        assert rp.assign(t, {"C3": det}, ["C3"], lenient=True) == ["p1"]

    def test_a_relation_part_needs_a_named_belief_that_states_the_relation(self):
        t = self._task("Cross-evidence link — prove the connection between USB content and network traffic.")
        diary = _node("C1", "The diary carved from the USB key holds the anti-forensics narrative.")
        same = _node("C2", "rhino1.jpg carved from the USB key is identical to the rhino1.jpg uploaded in the FTP session of the network capture.")
        assert rp.assign(t, {"C1": diary, "C2": same}, ["C1", "C2"], lenient=True) == []
        assert rp.assign(t, {"C1": diary, "C2": same}, ["C1"], explicit={"p1": ["C1"]}) == []
        assert rp.assign(t, {"C1": diary, "C2": same}, ["C2"], explicit={"p1": ["C2"]}) == ["p1"]

    def test_gone_beliefs_reopen_their_parts_and_a_successor_is_re_tested(self):
        t = self._task("Network — the delivery IP and the C2 IP.")
        nodes = {"N1": self.NET}
        rp.assign(t, nodes, ["N1"])
        nodes["N1"] = dict(self.NET, status="superseded")
        nodes["N2"] = _node("N2", "Network: delivery IP is 194.61.24.102; the C2 IP could not be established.", kind="conclusion")
        assert rp.carry(t, "N1", "N2", nodes) == ["p1", "p2"]
        assert t["parts"][0]["status"] == "answered" and t["parts"][1]["status"] == "open"
        nodes["N2"]["status"] = "withdrawn"
        assert rp.clear_gone(t, nodes) == ["p1"]

    def test_a_limitation_and_the_summary(self):
        t = self._task("Baseline — timezone, accounts.")
        rp.limit(t["parts"][1], "source_absent", "no SAM hive under config/", [12])
        assert t["parts"][1]["status"] == "limited" and t["parts"][1]["limitation"]["call_ids"] == [12]
        lines = rp.summary_lines(t)
        assert lines[0].endswith("open") and "not determined: source_absent" in lines[1]


class TestLimitationsThroughTheTool:
    """A limitation states why a part cannot be answered, with a basis the
    case can be held to: an absent source the case holds is refused, an
    examination cites the successful read, an unreadable source the failed
    read, an exclusion the brief's own words."""

    def _case(self, tmp_path, brief="**Case ID:** X\n\n## Investigation Requests\n- Baseline — timezone, accounts.\n"):
        from core.investigation_tasks import reconcile_case_md
        case = tmp_path / "X"
        (case / ".atlas").mkdir(parents=True)
        (case / "CASE.md").write_text(brief, encoding="utf-8")
        r = reconcile_case_md(case)
        return case, r["tasks"][0]["id"]

    def _trace(self, monkeypatch, entries):
        from core import execution_log
        class _Idx:
            by_call_id = entries
        monkeypatch.setattr(execution_log.log, "index", lambda: _Idx())

    def test_answered_is_refused_while_a_part_is_open_and_the_reply_names_it(self, tmp_path):
        from core.claim_graph import add_claim
        from core.investigation_tasks import update_task
        case, tid = self._case(tmp_path)
        cid = add_claim(case, "The time zone of the notebook is Central Standard Time (SYSTEM TimeZoneInformation).",
                        confidence="LIKELY", enforce_validation=False)["node_id"]
        r = update_task(case, tid, status="answered", related_claim_ids=[cid])
        assert not r["success"] and r["gate"] == "task_parts_open"
        assert "p2 accounts (needs a value of kind account)" in r["error"] and any("answered: Central Standard Time" in x for x in r["parts"])
        r = update_task(case, tid, status="partial", related_claim_ids=[cid])
        assert r["success"] and r["task"]["status"] == "partial"

    def test_an_absent_source_the_case_holds_is_refused(self, tmp_path, monkeypatch):
        from core.investigation_tasks import update_task
        case, tid = self._case(tmp_path)
        monkeypatch.setattr("core.artifact_value.known_artifacts",
                            lambda cd: {"evidence/tree/windows/system32/config/sam": {
                                "name": "SAM", "path": "evidence/tree/Windows/System32/config/SAM"}})
        r = update_task(case, tid, parts={"p2": {"limitation": {
            "basis": "source_absent", "reason": "no SAM hive was collected for the notebook"}}})
        assert not r["success"] and r["gate"] == "task_part_limitation"
        assert "'evidence/tree/Windows/System32/config/SAM' is present" in r["error"]
        r = update_task(case, tid, parts={"p2": {"limitation": {
            "basis": "source_absent", "reason": "no SECURITY hive was collected for the notebook"}}})
        assert r["success"] and r["task"]["parts"][1]["status"] == "limited"

    def test_examined_needs_a_successful_read_of_the_source(self, tmp_path, monkeypatch):
        from core.investigation_tasks import update_task
        case, tid = self._case(tmp_path)
        self._trace(monkeypatch, {
            12: {"mcp_tool": "misc:list_evidence_dir", "success": True, "cmd": "ls config/SAM"},
            13: {"mcp_tool": "ez:ez_recmd_hive", "success": True, "evidence_ref": "evidence/config/SAM"},
            14: {"mcp_tool": "ez:ez_recmd_hive", "success": False, "evidence_ref": "evidence/config/SAM", "stderr": "corrupt"},
        })
        bad = update_task(case, tid, parts={"p2": {"limitation": {
            "basis": "examined", "reason": "the SAM hive was parsed and lists no user account", "call_ids": [12]}}})
        assert not bad["success"] and "successful reader call" in bad["error"]
        good = update_task(case, tid, parts={"p2": {"limitation": {
            "basis": "examined", "reason": "the SAM hive was parsed and lists no user account", "call_ids": [13]}}})
        assert good["success"] and good["task"]["parts"][1]["limitation"]["call_ids"] == [13]
        unread = update_task(case, tid, parts={"p1": {"limitation": {
            "basis": "unreadable", "reason": "the SAM hive could not be parsed, the file is corrupt", "call_ids": [13]}}})
        assert not unread["success"]
        unread = update_task(case, tid, parts={"p1": {"limitation": {
            "basis": "unreadable", "reason": "the SAM hive could not be parsed, the file is corrupt", "call_ids": [14]}}})
        assert unread["success"] and unread["task"]["status"] == "blocked_missing_evidence"

    def test_out_of_scope_needs_the_briefs_exclusion(self, tmp_path):
        from core.investigation_tasks import update_task
        case, tid = self._case(tmp_path)
        r = update_task(case, tid, parts={"p2": {"limitation": {
            "basis": "out_of_scope", "reason": "the accounts are not asked for by the requester"}}})
        assert not r["success"]
        case2, tid2 = self._case(tmp_path / "b", "**Case ID:** Y\n\nAccounts are out of scope for this engagement.\n\n"
                                 "## Investigation Requests\n- Baseline — timezone, accounts.\n")
        r = update_task(case2, tid2, parts={"p2": {"limitation": {
            "basis": "out_of_scope", "reason": "the brief puts the accounts out of scope"}}})
        assert r["success"]


class TestReportPartLines:
    def test_the_answers_section_lists_each_part(self, tmp_path):
        from core.claim_graph import add_claim
        from core.investigation_tasks import reconcile_case_md, update_task
        from core.report_assemble import assemble_client_report
        case = tmp_path / "X"
        (case / ".atlas").mkdir(parents=True)
        (case / "CASE.md").write_text("**Case ID:** X\n\n## Investigation Requests\n"
                                      "- Network — the delivery IP and the C2 IP.\n", encoding="utf-8")
        tid = reconcile_case_md(case)["tasks"][0]["id"]
        cid = add_claim(case, "Network: delivery IP is 194.61.24.102 (external); the C2 IP could not be established.",
                        confidence="LIKELY", host="DC01", enforce_validation=False)["node_id"]
        update_task(case, tid, status="partial", related_claim_ids=[cid])
        update_task(case, tid, parts={"p2": {"limitation": {"basis": "source_absent",
                    "reason": "no proxy or firewall log covers the beacon window"}}})
        text = assemble_client_report(case)
        assert "Parts of the request" in text
        assert "- the delivery IP: answered 194.61.24.102" in text
        assert "- the C2 IP: not determined — source_absent: no proxy or firewall log covers the beacon window" in text


class TestStandardParts:
    def test_an_umbrella_gets_the_tables_parts_per_computer(self):
        parts = rp.standard_parts("What happened on the hosts?", ["DC01", "WS07"])
        assert [p["text"] for p in parts][:4] == ["affected on DC01", "affected on WS07",
                                                  "initial activity on DC01", "initial activity on WS07"]
        assert all(p["kind"] == "standard" for p in parts) and parts[0]["gate"] and parts[0]["host"] == "DC01"
        assert rp.standard_parts("What happened on the hosts?", []) [0]["text"] == "affected"
        assert [p["text"] for p in rp.standard_parts("Did data get stolen, and if yes which one?", ["DC01"])][:2] == [
            "data taken", "the files or data sets taken"]
        assert rp.standard_parts("Which accounts were created?", ["DC01"]) == []

    def test_a_host_answered_not_affected_closes_its_other_parts(self):
        task = {"text": "What happened on the hosts?", "status": "open", "related_claim_ids": []}
        rp.ensure_parts(task)
        assert rp.ensure_standard_parts(task, ["DC01", "WS07"])
        assert not rp.ensure_standard_parts(task, ["DC01", "WS07"])
        clean = _node("C1", "No sign of compromise was found on WS07: no foreign logon, no persistence, no beacon.", host="WS07")
        clean["evidence"] = [{"call_id": 41}]
        gate = next(p for p in task["parts"] if p["text"] == "affected on WS07")
        rp.assign(task, {"C1": clean}, ["C1"], explicit={gate["id"]: ["C1"]})
        assert gate["status"] == "answered"
        closed = rp.close_unaffected_hosts(task, {"C1": clean})
        assert len(closed) == 5
        ws07 = [p for p in task["parts"] if p.get("host") == "WS07" and p["kind"] == "standard"]
        assert all(p["status"] in ("answered", "limited") for p in ws07)
        assert all(p["status"] == "open" for p in task["parts"] if p.get("host") == "DC01")
        limited = next(p for p in ws07 if p["status"] == "limited")
        assert limited["limitation"]["basis"] == "examined" and limited["limitation"]["call_ids"] == [41]

    def test_a_per_host_part_takes_that_hosts_belief_only(self):
        task = {"text": "What happened on the hosts?", "status": "open", "related_claim_ids": []}
        rp.ensure_parts(task); rp.ensure_standard_parts(task, ["DC01", "WS07"])
        first = _node("C2", "Initial attacker activity on DC01 began at 2020-09-19 02:19 UTC with an RDP logon.", host="DC01")
        done = rp.assign(task, {"C2": first}, ["C2"])
        texts = {p["id"]: p for p in task["parts"]}
        assert [texts[i]["text"] for i in done] == ["initial activity on DC01"]


class TestValueTable:
    def test_the_mft_rule_is_anchored_and_syscache_is_demoted(self):
        from core.artifact_value import artifact_score
        assert artifact_score("$MFT", 100_000)[0] == 85
        assert artifact_score("C/$MFTMirr", 4096)[0] < 85
        assert artifact_score("mft.csv", 4096)[0] == 85
        assert artifact_score("Windows/AppCompat/Programs/Amcache.hve", 4096)[0] >= 80
        assert artifact_score("Windows/AppCompat/Programs/Syscache.hve", 4096)[0] == 60
        assert artifact_score("Windows/System32/config/SYSTEM", 4096)[0] == 82


class TestReviewedFixes:
    """Ids and technical tokens are not hosts, a name after "named" is the
    account, a bare file needs a known extension, naming a belief waives the
    part's qualifier, a short request with a table intent takes the table's
    parts, a gate cites the finding's calls, and the umbrella part follows
    its sub-questions."""

    def test_ids_and_technical_tokens_are_not_hosts_and_known_hosts_win(self):
        text = "Device and system baseline (task-0001): the E01 image, computer name N-1A9ODN6ZXK4LQ, SP2, MD5 verified; claim C0009; DC01"
        assert [v for v, _ in av.values(text, "host")] == ["N-1A9ODN6ZXK4LQ", "DC01"]
        assert [v for v, _ in av.values(text, "host", known_hosts=["DC01"])][0] == "DC01"
        assert av.bind("computer name", "host", "The computer name is N-1A9ODN6ZXK4LQ (task-0001).")[0] == "N-1A9ODN6ZXK4LQ"

    def test_named_accounts_and_bare_files(self):
        assert [v for v, _ in av.values("The user named jimcloudy1 owns the laptop; user creation followed", "account")] == ["jimcloudy1"]
        assert [v for v, _ in av.values("signed URLs at signin.aws and the file rootkey.csv", "path")] == ["rootkey.csv"]

    def test_naming_a_belief_waives_the_qualifier(self):
        st = "Initial access to DC01 via RDP brute force from external IP 194.61.24.102 at 2020-09-19 02:21 UTC."
        assert av.bind("the source address", "ip", st) == (None, "")
        assert av.bind("the source address", "ip", st, explicit=True)[0] == "194.61.24.102"
        assert av.bind("when access was gained", "datetime", st, explicit=True)[0] == "2020-09-19 02:21 UTC"
        t = {"text": "How did the attacker gain access to the network?", "status": "open", "related_claim_ids": []}
        rp.ensure_parts(t); rp.ensure_standard_parts(t, [])
        node = _node("C1", st, host="DC01")
        src = next(p for p in t["parts"] if p["text"] == "the source address")
        assert rp.assign(t, {"C1": node}, ["C1"]) == []
        assert src["id"] in rp.assign(t, {"C1": node}, ["C1"], explicit={src["id"]: ["C1"]})
        assert src["value"] == "194.61.24.102"

    def test_a_short_request_with_a_table_intent_takes_the_tables_parts(self):
        for text, first in (("Did Data get stolen, and if yes which one?", "data taken"),
                            ("How did the Attacker gain Access to the Network?", "the access vector"),
                            ("What type of Attack was it?", "the incident type")):
            t = {"text": text, "status": "open", "related_claim_ids": []}
            rp.ensure_parts(t)
            assert rp.ensure_standard_parts(t, ["HOST-A"])
            assert t["parts"][0]["text"] == first and all(p["kind"] == "standard" for p in t["parts"])
            assert not rp.ensure_standard_parts(t, ["HOST-A"])
        long = {"text": "Network identity — installed NICs, IP and MAC, and which card was in use.", "status": "open", "related_claim_ids": []}
        rp.ensure_parts(long)
        assert not rp.ensure_standard_parts(long, ["HOST-A"])

    def test_the_gate_cites_the_findings_calls_and_the_umbrella_follows_its_parts(self):
        task = {"text": "What happened on the hosts?", "status": "open", "related_claim_ids": []}
        rp.ensure_parts(task); rp.ensure_standard_parts(task, ["WS07"])
        clean = _node("C1", "No sign of compromise was found on WS07: no foreign logon, no persistence, no beacon.", host="WS07")
        clean["evidence"] = [{"artifact": "evidence/ws07.E01", "locator": "offset 2048", "call_id": 41, "size": 4096}]
        clean["source_finding_call_id"] = 57
        gate = next(p for p in task["parts"] if p["text"] == "affected on WS07")
        rp.assign(task, {"C1": clean}, ["C1"], explicit={gate["id"]: ["C1"]})
        rp.close_unaffected_hosts(task, {"C1": clean})
        limited = next(p for p in task["parts"] if p["status"] == "limited")
        assert limited["limitation"]["call_ids"] == [41, 57]
        assert rp.settle_umbrella(task)
        umbrella = next(p for p in task["parts"] if p["kind"] == "umbrella")
        assert umbrella["status"] == "answered" and umbrella["claim_ids"] == ["C1"]
        assert rp.derive_status(task) == "answered"

    def test_the_pre_report_text_names_the_accepted_bases(self):
        """One JSON example, the shape the tool takes, and every basis by
        name; no pseudo-code a model would echo as a string."""
        import inspect
        import json as _json
        import tools.reasoning as reasoning
        from core.investigation_tasks import PARTS_EXAMPLE, PARTS_HOW
        example = _json.loads(PARTS_EXAMPLE)
        assert all(isinstance(v, dict) for v in example.values())
        assert all(b in PARTS_HOW for b in rp.LIMITATION_BASES) and PARTS_EXAMPLE in PARTS_HOW
        src = inspect.getsource(reasoning._task_disposition_for_report)
        assert "PARTS_HOW" in src and "parts={" not in src


class TestUmbrellaFollowsItsParts:
    def test_the_umbrella_never_closes_ahead_of_its_sub_questions(self):
        task = {"text": "What happened on the hosts?", "status": "open", "related_claim_ids": []}
        rp.ensure_parts(task); rp.ensure_standard_parts(task, ["WS07"])
        node = _node("C1", "Ransomware was found on WS07 after an RDP logon at 2025-01-02 10:00 UTC.", host="WS07")
        rp.assign(task, {"C1": node}, ["C1"], lenient=True)
        umbrella = next(p for p in task["parts"] if p["kind"] == "umbrella")
        assert umbrella["status"] == "open"
        for p in task["parts"]:
            if p["kind"] == "standard":
                p["status"] = "answered"; p["claim_ids"] = ["C1"]
        assert rp.settle_umbrella(task) and umbrella["status"] == "answered"
        task["parts"][1]["status"] = "open"; task["parts"][1]["claim_ids"] = []
        assert rp.settle_umbrella(task) and umbrella["status"] == "open"


class TestStrictKindsAndTheAnalystsLink:
    """A link alone answers a part only for kinds whose value prose can state
    in ways no pattern reads; an ip, mac, email, hash or domain part needs a
    belief that states the value."""

    def _part_task(self, part_text, typ):
        return {"text": "Web activity", "status": "open", "related_claim_ids": [],
                "parts": [{"id": "p1", "text": part_text, "type": typ, "kind": "value", "status": "open",
                           "claim_ids": [], "value": "", "limitation": {}}]}

    def test_a_domain_part_is_not_answered_by_a_linked_belief_without_a_site(self):
        t = self._part_task("which sites the contractor was visiting", "domain")
        node = _node("C1", "The contractor was visiting sites and captured credentials of the operator.")
        assert rp.assign(t, {"C1": node}, ["C1"], explicit={"p1": ["C1"]}, lenient=True) == []

    def test_the_same_part_is_answered_by_a_belief_naming_a_site(self):
        t = self._part_task("which sites the contractor was visiting", "domain")
        node = _node("C1", "The contractor was visiting evil.xyz and captured credentials of the operator.")
        assert rp.assign(t, {"C1": node}, ["C1"], explicit={"p1": ["C1"]}, lenient=True) == ["p1"]
        assert t["parts"][0]["value"] == "evil.xyz"

    def test_an_account_part_keeps_the_link(self):
        t = self._part_task("the chat account the operator used", "account")
        node = _node("C1", "The operator used the chat account with nick=shadowfox on the relay network.")
        assert rp.assign(t, {"C1": node}, ["C1"], explicit={"p1": ["C1"]}, lenient=True) == ["p1"]


class TestTypedIndicatorBinding:
    """A belief that types one of two values of the part's kind answers with
    that value, whatever the word distance: the analyst's typing says which
    value the belief is about."""

    ST = "Beacon-over-HTTP C2 channel from HOST-A (10.0.0.5) to 203.0.113.9:80, repeated every 60 s."

    def test_without_typing_the_nearest_value_stands(self):
        assert av.bind("the C2 IP", "ip", self.ST, explicit=True)[0] == "10.0.0.5"

    def test_a_typed_indicator_is_preferred_on_every_path(self):
        assert av.bind("the C2 IP", "ip", self.ST, explicit=True, prefer=["203.0.113.9"])[0] == "203.0.113.9"
        assert av.bind("the C2 IP", "ip", self.ST, prefer=["203.0.113.9"])[0] == "203.0.113.9"
        assert av.bind("the IP", "ip", self.ST, prefer=["203.0.113.9"])[0] == "203.0.113.9"

    def test_typing_both_values_keeps_the_distance_order(self):
        assert av.bind("the C2 IP", "ip", self.ST, explicit=True,
                       prefer=["10.0.0.5", "203.0.113.9"])[0] == "10.0.0.5"

    def test_the_part_takes_the_value_its_linked_belief_types(self):
        t = {"text": "Network — the delivery IP and the C2 IP.", "status": "open", "related_claim_ids": []}
        rp.ensure_parts(t)
        node = dict(_node("C1", self.ST, host="HOST-A"),
                    indicators=[{"type": "ip", "value": "203.0.113.9", "side": "attacker"}])
        c2 = next(p for p in t["parts"] if "C2" in p["text"])
        assert c2["id"] in rp.assign(t, {"C1": node}, ["C1"], explicit={c2["id"]: ["C1"]})
        assert c2["value"] == "203.0.113.9"


class TestDefaultTypedPartsJudgedOnTheirOwnWords:
    """A part whose words name no kind, in a request with several parts, is
    answered only by a belief that speaks to the part itself."""

    REQUEST = ("Network traces — file transfers in all three pcaps (FTP, HTTP, an encrypted zip and "
               "its password, an executable).")
    HTTP = ("Suspect 10.0.0.34 downloaded alpha4.jpg and alpha5.gif via HTTP from www.example.edu "
            "(10.0.0.37) in capture2.pcap.")
    FTP = "An FTP session in capture.pcap uploaded bundle.zip to 10.0.0.40:21 as USER jdoe."

    def _task(self):
        t = {"text": self.REQUEST, "status": "open", "related_claim_ids": []}
        rp.ensure_parts(t)
        return t

    def test_a_belief_about_the_request_answers_only_the_parts_it_speaks_to(self):
        t = self._task()
        nodes = {"C1": _node("C1", self.HTTP)}
        rp.assign(t, nodes, ["C1"], lenient=True)
        status = {p["text"]: p["status"] for p in t["parts"]}
        assert status["HTTP"] == "answered"
        assert status["FTP"] == "open"
        assert status["an encrypted zip and its password"] == "open"

    def test_the_belief_that_speaks_to_the_part_answers_it(self):
        t = self._task()
        nodes = {"C1": _node("C1", self.HTTP), "C2": _node("C2", self.FTP)}
        rp.assign(t, nodes, ["C1", "C2"], lenient=True)
        ftp = next(p for p in t["parts"] if p["text"] == "FTP")
        assert ftp["status"] == "answered" and ftp["claim_ids"] == ["C2"]


class TestANamedBeliefAnswersADefaultPartInAnyClause:
    """A belief the analyst named for a part whose words name no kind answers
    it through any clause that carries the part's words; a belief only linked
    to the task needs them in its lead. A statement that reports a gap
    answers nothing."""

    REQUEST = "Anti-forensics — applied separately on KEY-0, on KEY-1, and on KEY-2."
    COMBINED = ("Anti-forensics on KEY-1: every file on the FAT32 volume was deleted, leaving "
                "orphaned entries. Anti-forensics on KEY-2: the disc was burned as a UDF session.")

    def _task(self):
        t = {"text": self.REQUEST, "status": "open", "related_claim_ids": []}
        rp.ensure_parts(t)
        return t, {p["text"]: p for p in t["parts"]}

    def test_a_named_belief_answers_each_part_it_walks_through(self):
        t, by = self._task()
        ids = [by["on KEY-1"]["id"], by["on KEY-2"]["id"]]
        rp.assign(t, {"C1": _node("C1", self.COMBINED)}, ["C1"],
                  explicit={i: ["C1"] for i in ids}, lenient=True)
        assert by["on KEY-1"]["status"] == "answered"
        assert by["on KEY-2"]["status"] == "answered" and by["on KEY-2"]["bound_by"] == "analyst"

    def test_a_linked_belief_answers_only_the_part_its_lead_carries(self):
        t, by = self._task()
        rp.assign(t, {"C1": _node("C1", self.COMBINED)}, ["C1"], lenient=True)
        assert by["on KEY-1"]["status"] == "answered"
        assert by["on KEY-2"]["status"] == "open"

    def test_a_later_gap_answers_nothing(self):
        t, by = self._task()
        node = _node("C1", "Anti-forensics on KEY-1: every file was deleted. KEY-2 was not examined "
                           "(its image is unreadable).")
        rp.assign(t, {"C1": node}, ["C1"], explicit={by["on KEY-2"]["id"]: ["C1"]}, lenient=True)
        assert by["on KEY-2"]["status"] == "open"

    def test_a_later_statement_that_nothing_was_found_answers_its_part(self):
        t, by = self._task()
        node = _node("C1", "Anti-forensics on KEY-1: every file was deleted. On KEY-2 no wiping "
                           "tool artifacts were found.")
        rp.assign(t, {"C1": node}, ["C1"], explicit={by["on KEY-2"]["id"]: ["C1"]}, lenient=True)
        assert by["on KEY-2"]["status"] == "answered" and by["on KEY-2"]["bound_by"] == "analyst"

    def test_a_named_belief_about_another_part_stays_refused(self):
        t = {"text": TestDefaultTypedPartsJudgedOnTheirOwnWords.REQUEST, "status": "open",
             "related_claim_ids": []}
        rp.ensure_parts(t)
        ftp = next(p for p in t["parts"] if p["text"] == "FTP")
        node = _node("C1", TestDefaultTypedPartsJudgedOnTheirOwnWords.HTTP)
        rp.assign(t, {"C1": node}, ["C1"], explicit={ftp["id"]: ["C1"]}, lenient=True)
        assert ftp["status"] == "open"

    def test_a_successor_keeps_the_part_through_a_later_clause(self):
        t, by = self._task()
        key2 = by["on KEY-2"]
        nodes = {"C1": _node("C1", self.COMBINED)}
        rp.assign(t, nodes, ["C1"], explicit={key2["id"]: ["C1"]}, lenient=True)
        nodes["C2"] = _node("C2", self.COMBINED.replace("UDF session", "UDF session at 10:02 UTC"))
        nodes["C1"]["status"] = "superseded"
        rp.carry(t, "C1", "C2", nodes)
        assert key2["status"] == "answered" and key2["claim_ids"] == ["C2"]


def test_a_value_part_is_not_answered_by_a_later_absence_in_its_named_belief():
    t = {"text": "Accounts", "status": "open", "related_claim_ids": [],
         "parts": [{"id": "p1", "text": "the chat account on KEY-2", "type": "account", "kind": "value",
                    "status": "open", "claim_ids": [], "value": "", "limitation": {}}]}
    node = _node("C1", "Mail on KEY-1 was read in a webmail session. On KEY-2 no chat account was found.")
    assert rp.assign(t, {"C1": node}, ["C1"], explicit={"p1": ["C1"]}, lenient=True) == []


def test_a_single_part_is_not_answered_through_its_requests_label():
    t = {"text": "Ransomware — the demand amount.", "status": "open", "related_claim_ids": []}
    rp.ensure_parts(t)
    node = _node("C1", "Ransomware persistence runs via a scheduled task named UpdateCheck at every login.")
    pid = t["parts"][0]["id"]
    rp.assign(t, {"C1": node}, ["C1"], explicit={pid: ["C1"]}, lenient=True)
    assert t["parts"][0]["status"] == "open"


class TestNumberedNames:
    """"USB#2" and "USB#3" share every word the part tests compare: a belief
    answers the part's numbered name only when it writes that number."""

    USB3 = _node("C1", "Files were copied to USB#3 at 2031-03-04 10:00 UTC.")

    @pytest.mark.parametrize("text, carried", [
        ("copied to usb #2", True), ("USB-2", True), ("USB 2", True), ("USB2", True), ("USB#02", True),
        ("USB#3", False), ("USB#20", False), ("XUSB#2", False),
    ])
    def test_the_number_is_carried_with_any_separator(self, text, carried):
        assert rp.anchors_carried("on USB#2", text) is carried

    def test_the_hyphen_form_counts_in_capitals_only(self):
        assert rp.anchors_carried("Was RM-3 accessed?", "rm3 was accessed")
        assert not rp.anchors_carried("Was RM-3 accessed?", "RM-4 was accessed")
        assert rp.anchors_carried("the Windows-10 build", "Windows 11")
        assert rp.anchors_carried("on CORP-DC-01", "CORP-DC02")

    @pytest.mark.parametrize("named", [False, True])
    def test_a_belief_about_one_numbered_device_leaves_its_sibling_open(self, named):
        t = {"text": "Removable media — activity on USB#2, activity on USB#3.", "status": "open",
             "related_claim_ids": []}
        rp.ensure_parts(t)
        explicit = {"p1": ["C1"], "p2": ["C1"]} if named else None
        assert rp.assign(t, {"C1": self.USB3}, ["C1"], explicit=explicit, lenient=True) == ["p2"]

    @pytest.mark.parametrize("named", [False, True])
    def test_a_value_part_takes_no_value_from_its_siblings_belief(self, named):
        t = {"text": "Removable media — the serial number of USB#2, the serial number of USB#3.",
             "status": "open", "related_claim_ids": []}
        rp.ensure_parts(t)
        node = _node("C1", "USB#3 (serial 1234567890AB) was attached to CORP-WS01 on 2031-03-04.")
        explicit = {"p1": ["C1"], "p2": ["C1"]} if named else None
        assert rp.assign(t, {"C1": node}, ["C1"], explicit=explicit, lenient=True) == ["p2"]

    def test_a_kinds_own_name_is_no_numbered_name(self):
        assert rp.anchors_carried("the SHA-256 of the dropper", "The dropper hashes to 3f2a...")

    def test_a_yes_no_part_reads_the_number_in_the_clause(self):
        t = {"text": "Removable media — whether files were copied to USB#2.", "status": "open",
             "related_claim_ids": []}
        rp.ensure_parts(t)
        assert rp.assign(t, {"C1": self.USB3}, ["C1"], explicit={"p1": ["C1"]}, lenient=True) == []
        usb2 = _node("C2", "Files were copied to USB #2 at 2031-03-04 10:00 UTC.")
        assert rp.assign(t, {"C2": usb2}, ["C2"], explicit={"p1": ["C2"]}, lenient=True) == ["p1"]


def test_a_yes_no_part_is_answered_by_a_lead_that_asserts_it_despite_a_trailing_caveat():
    # "encrypted" and "encryption" share a stem; the caveat after "; " is no gap.
    t = {"text": "Ransomware — was the share encrypted?", "status": "open", "related_claim_ids": []}
    rp.ensure_parts(t)
    node = _node("C1", "Encryption of the share began at 2031-01-01 10:00 UTC; the ransom note could not "
                       "be recovered.")
    assert rp.assign(t, {"C1": node}, ["C1"], lenient=True) == ["p1"]
