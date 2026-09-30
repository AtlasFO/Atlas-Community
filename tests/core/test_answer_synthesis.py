"""Answers to questions, and names for findings.

A belief that lists what was never looked at (an "absence hypothesis"
naming unexamined evidence categories) is a statement about the
investigation, not about the case. The rule under test is that such a
statement can qualify an answer but may never be one.
"""
from __future__ import annotations

import httpx
import pytest

from core import answer_synthesis as syn
from core import providers

GAP_CLAIM = {
    "id": "C0006", "confidence": "SUSPECTED", "status": "new",
    "statement": ("Absence hypothesis (H0004) lists 5 evidence categories "
                  "left unexamined for data exfiltration: (1) CORP-DC01 "
                  "System and Application EVTX, (2) removable media and USB "
                  "artifacts."),
}
STAGING_CLAIM = {
    "id": "C0007", "confidence": "SUSPECTED", "status": "new",
    "host": "CORP-SRV01",
    "statement": ("7-Zip installer (7z-x64.exe, 1,500,000 bytes) found "
                  "in Downloads on CORP-SRV01. This archiving tool could be "
                  "used for data staging before exfiltration."),
}
FIREWALL_CLAIM = {
    "id": "C0004", "confidence": "UNCONFIRMED", "status": "new",
    "statement": ("Firewall logs contain only internal management traffic. "
                  "No external destination IPs and no outbound data transfers "
                  "visible."),
}


class TestClassification:
    def test_unexamined_evidence_is_a_gap_not_a_finding(self):
        assert syn.classify_statement(GAP_CLAIM["statement"]) == syn.GAP

    def test_an_assertion_is_affirmative(self):
        assert syn.classify_statement(STAGING_CLAIM["statement"]) == syn.AFFIRMATIVE

    def test_a_negative_result_is_an_absence_not_a_gap(self):
        """'We looked and it is not there' is a finding; 'we never looked'
        is not. Conflating them lets a gap pose as an answer."""
        assert syn.classify_statement(FIREWALL_CLAIM["statement"]) == syn.ABSENCE
        assert syn.classify_statement(
            "Standard Windows artifacts are absent from CORP-SRV01") == syn.ABSENCE


class TestAnswerSynthesis:
    def test_a_gap_never_leads_the_answer(self):
        a = syn.synthesize_answer(
            "Are there signs of Data Exfiltration?",
            [GAP_CLAIM, STAGING_CLAIM, FIREWALL_CLAIM])
        assert not a["text"].startswith("Absence hypothesis")
        assert "7-Zip" in a["text"]
        assert a["gaps"], "the gap is kept, as a stated limitation"
        assert "limited" in a["text"]

    def test_an_indication_is_not_a_verdict(self):
        """"Any exfiltration?" asks yes or no; a staging tool that merely
        could serve exfiltration is an indication, said as one."""
        a = syn.synthesize_answer("Any exfiltration?", [STAGING_CLAIM])
        assert a["verdict"] == "Possible indicators, weakly supported"
        assert a["text"].startswith("Indications only") and "7-Zip" in a["text"]
        assert a["lead"].startswith("Indications only")

    def test_only_negative_evidence_yields_a_negative_verdict(self):
        a = syn.synthesize_answer("Any exfiltration?", [FIREWALL_CLAIM])
        assert a["verdict"] == "No supporting evidence found"

    def test_only_gaps_is_reported_as_not_established(self):
        a = syn.synthesize_answer("Any exfiltration?", [GAP_CLAIM])
        assert "Not established" in a["verdict"]
        assert syn.answer_is_only_gaps(a)

    def test_no_claims_is_not_an_answer(self):
        a = syn.synthesize_answer("What happened?", [])
        assert a["verdict"] == "Not answered"
        assert not syn.answer_is_only_gaps(a)

    def test_withdrawn_beliefs_are_excluded(self):
        dead = dict(STAGING_CLAIM, status="withdrawn")
        assert syn.synthesize_answer("q", [dead])["verdict"] == "Not answered"

    def test_hosts_and_timespan_are_surfaced(self):
        claim = dict(STAGING_CLAIM,
                     evidence=[{"timestamp": "2031-02-04T12:00:00Z"},
                               {"timestamp": "2031-02-04T18:30:00Z"}])
        a = syn.synthesize_answer("q", [claim])
        assert a["hosts"] == ["CORP-SRV01"]
        assert "2031-02-04 12:00:00 UTC" in a["timespan"]


class TestHeadline:
    def test_a_headline_is_a_name_not_the_whole_statement(self):
        h = syn.headline(
            "Encrypted file notes.txt.locked (11,000 bytes) found in the "
            "root directory of CORP-SRV01. The .locked extension is "
            "consistent with ransomware file encryption. SHA256: 0f1e2d…")
        assert h.startswith("Encrypted file notes.txt.locked")
        assert "SHA256" not in h
        assert len(h) <= syn.MAX_HEADLINE + 1

    def test_a_headline_does_not_end_on_a_dangling_verb(self):
        h = syn.headline(
            "CORP-DC01 MFT timeline shows: root directory modified Feb 4 "
            "12:10, $Recycle.Bin modified Feb 4 12:00, the EDR sensor driver "
            "installed and many further entries besides these ones here")
        assert not h.rstrip("…").endswith("shows")

    def test_headlines_are_stable(self):
        s = "Credential-dumping driver installed as a kernel service on CORP-SRV01."
        assert syn.headline(s) == syn.headline(s)

    def test_empty_in_empty_out(self):
        assert syn.headline("") == ""


SCAFFOLD = {
    "text": "Ransomware was found on CORP-SRV01.",
    "points": ["Ransomware on CORP-SRV01"],
    "hosts": ["CORP-SRV01"],
    "timespan": "2031-02-04 12:00 → 2031-02-05 09:00",
    "verdict": "Indicators found",
    "confidence": "LIKELY",
    "gaps": [],
    "supporting": [{"id": "C0001", "status": "new", "confidence": "LIKELY"}],
}
# The scaffold the prose pass works on: the renderer's lead sentence and
# the supporting headline the model may carry under it.
LEAD = "Ransomware was found on CORP-SRV01."
SUPPORT = "The svc.backup01 account dropped the ransom note at 2031-02-04 12:00 UTC"
LEAD_SCAFFOLD = {
    "text": f"{LEAD} {SUPPORT}.",
    "lead": LEAD,
    "points": ["Ransomware on CORP-SRV01", SUPPORT],
    "hosts": ["CORP-SRV01"],
    "timespan": "2031-02-04 12:00 → 2031-02-05 09:00",
    "verdict": "Lead finding",
    "confidence": "LIKELY",
    "gaps": [],
    "supporting": [{"id": "C0001", "status": "new", "confidence": "LIKELY"}],
}
GOOD_PROSE = "The svc.backup01 account dropped the ransom note at 2031-02-04 12:00 UTC."


class _Provider:
    name = "llmhub"
    model = "a-model"
    base_url = "https://endpoint.example/v1"
    api_key = "k"


class _NoKeyProvider:
    name = "llmhub"
    model = ""
    base_url = ""
    api_key = ""


def _chat_body(content="An answer.", finish="stop"):
    return {"choices": [{"message": {"role": "assistant", "content": content},
                         "finish_reason": finish}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 5}}


class _Resp:
    def __init__(self, body, status=200):
        self._body, self.status_code, self.text = body, status, ""

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._body


@pytest.fixture
def llm_reply(monkeypatch, tmp_path):
    """Fake the transport under ``synthesize_answer_text`` the same way the
    report-section generator's own tests do."""
    captured: dict = {}
    monkeypatch.setattr(providers, "resolve", lambda *a, **k: _Provider())
    monkeypatch.setattr(providers, "role_name", lambda *a, **k: "llmhub")
    from agent import llm as _llm
    monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(tmp_path / "compat.json"))
    _llm.clear_api_compat_cache(memory_only=True)

    def _post(url, json=None, headers=None, timeout=None):
        captured["body"] = json or {}
        return _Resp(captured.get("reply") or _chat_body())

    monkeypatch.setattr(httpx, "post", _post)
    return captured


class TestScaffoldFingerprint:
    def test_stable_for_an_identical_scaffold(self):
        assert (syn.scaffold_fingerprint(dict(SCAFFOLD))
               == syn.scaffold_fingerprint(dict(SCAFFOLD)))

    def test_changes_when_a_supporting_claim_changes_status(self):
        other = dict(SCAFFOLD, supporting=[
            {"id": "C0001", "status": "superseded", "confidence": "LIKELY"}])
        assert syn.scaffold_fingerprint(SCAFFOLD) != syn.scaffold_fingerprint(other)

    def test_changes_when_the_deterministic_text_changes(self):
        other = dict(SCAFFOLD, text="Something else entirely.")
        assert syn.scaffold_fingerprint(SCAFFOLD) != syn.scaffold_fingerprint(other)


class TestAnswerTextCache:
    def test_round_trip(self, tmp_path):
        syn._save_cache(tmp_path, {"task-1": {"text": "hello", "fingerprint": "abc"}})
        assert syn.cached_answer_text(tmp_path, "task-1", "abc") == "hello"

    def test_a_fingerprint_mismatch_is_a_miss(self, tmp_path):
        syn._save_cache(tmp_path, {"task-1": {"text": "hello", "fingerprint": "abc"}})
        assert syn.cached_answer_text(tmp_path, "task-1", "different") is None

    def test_no_cache_file_is_a_miss(self, tmp_path):
        assert syn.cached_answer_text(tmp_path, "task-1", "abc") is None


class TestGrounding:
    def test_text_built_only_from_scaffold_facts_passes(self):
        assert syn._grounded("On CORP-SRV01, ransomware was found.", SCAFFOLD)

    def test_a_host_shaped_token_not_in_the_scaffold_fails(self):
        assert not syn._grounded("CORP-DC02 was also affected.", SCAFFOLD)

    def test_an_invented_hash_fails(self):
        text = "The payload's hash is a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6."
        assert not syn._grounded(text, SCAFFOLD)


class TestSynthesizeAnswerText:
    def test_no_provider_configured_returns_the_deterministic_text(
            self, monkeypatch, tmp_path):
        monkeypatch.setattr(providers, "role_name", lambda *a, **k: "llmhub")
        monkeypatch.setattr(providers, "resolve", lambda *a, **k: _NoKeyProvider())
        out = syn.synthesize_answer_text(tmp_path, "task-1", "What happened?", LEAD_SCAFFOLD)
        assert out == LEAD_SCAFFOLD["text"]

    def test_a_grounded_reply_is_returned_under_the_lead_and_then_served_from_cache(
            self, llm_reply, tmp_path):
        llm_reply["reply"] = _chat_body(content=GOOD_PROSE)
        out = syn.synthesize_answer_text(tmp_path, "task-1", "What happened?", LEAD_SCAFFOLD)
        assert out == f"{LEAD} {GOOD_PROSE}"
        # The model saw the support, never the lead as something to write.
        sent = llm_reply["body"]["messages"][1]["content"]
        assert SUPPORT in sent and "first_sentence_already_written" in sent

        def _fail(*a, **k):
            raise AssertionError("must not call the LLM again — cache should hit")
        import httpx as _h
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(_h, "post", _fail)
            out2 = syn.synthesize_answer_text(tmp_path, "task-1", "What happened?", LEAD_SCAFFOLD)
        assert out2 == out

    def test_an_ungrounded_reply_falls_back_to_deterministic(self, llm_reply, tmp_path):
        llm_reply["reply"] = _chat_body(content="CORP-DC02 was compromised too.")
        out = syn.synthesize_answer_text(tmp_path, "task-1", "What happened?", LEAD_SCAFFOLD)
        assert out == LEAD_SCAFFOLD["text"]

    def test_an_empty_reply_falls_back_to_deterministic(self, llm_reply, tmp_path):
        llm_reply["reply"] = _chat_body(content="", finish="length")
        out = syn.synthesize_answer_text(tmp_path, "task-1", "What happened?", LEAD_SCAFFOLD)
        assert out == LEAD_SCAFFOLD["text"]

    def test_a_truncated_reply_falls_back_to_deterministic(self, llm_reply, tmp_path):
        llm_reply["reply"] = _chat_body(content="The svc.backup01 account dropped the", finish="length")
        out = syn.synthesize_answer_text(tmp_path, "task-1", "What happened?", LEAD_SCAFFOLD)
        assert out == LEAD_SCAFFOLD["text"]

    def test_a_reply_that_states_a_relation_falls_back(self, llm_reply, tmp_path):
        llm_reply["reply"] = _chat_body(
            content=GOOD_PROSE + " This proves the account and the ransomware are linked.")
        out = syn.synthesize_answer_text(tmp_path, "task-1", "What happened?", LEAD_SCAFFOLD)
        assert out == LEAD_SCAFFOLD["text"]

    def test_a_scaffold_without_a_lead_or_with_only_the_lead_stays_deterministic(
            self, llm_reply, tmp_path):
        out = syn.synthesize_answer_text(tmp_path, "task-1", "What happened?", SCAFFOLD)
        assert out == SCAFFOLD["text"] and "body" not in llm_reply
        only_lead = dict(LEAD_SCAFFOLD, points=["Ransomware on CORP-SRV01"], text=LEAD)
        out = syn.synthesize_answer_text(tmp_path, "task-2", "What happened?", only_lead)
        assert out == LEAD and "body" not in llm_reply

    def test_not_established_and_conclusion_leads_are_never_sent(self, llm_reply, tmp_path):
        ne = dict(LEAD_SCAFFOLD, verdict="Not established — no finding addresses this question directly",
                  lead="Not established — no finding addresses this question directly.",
                  text="Not established — no finding addresses this question directly. Related: Ransomware on CORP-SRV01.")
        assert syn.synthesize_answer_text(tmp_path, "task-3", "Which files?", ne) == ne["text"]
        cl = dict(LEAD_SCAFFOLD, conclusion_lead=True)
        assert syn.synthesize_answer_text(tmp_path, "task-4", "What happened?", cl) == cl["text"]
        assert "body" not in llm_reply

    def test_a_transport_error_falls_back_to_deterministic(self, monkeypatch, tmp_path):
        monkeypatch.setattr(providers, "resolve", lambda *a, **k: _Provider())
        monkeypatch.setattr(providers, "role_name", lambda *a, **k: "llmhub")

        def _boom(*a, **k):
            raise RuntimeError("network down")
        monkeypatch.setattr(httpx, "post", _boom)
        out = syn.synthesize_answer_text(tmp_path, "task-1", "What happened?", SCAFFOLD)
        assert out == SCAFFOLD["text"]

    def test_no_deterministic_text_means_no_llm_call_at_all(self, tmp_path):
        def _boom(*a, **k):
            raise AssertionError("must not attempt a call with nothing to ground it in")
        empty = dict(SCAFFOLD, text="")
        assert syn.synthesize_answer_text(tmp_path, "task-1", "What happened?", empty) == ""


class TestFirstSentence:
    """A full stop inside a title, an initial or an abbreviation is not the
    end of a sentence; a headline cut there loses the fact it carries."""

    def test_a_title_does_not_end_the_sentence(self):
        s = ("Intercepted capture (e0030703.pcap in Mr. Evil profile): victim device "
             "192.168.254.2. Captured session cookies.")
        assert syn.first_sentence(s) == (
            "Intercepted capture (e0030703.pcap in Mr. Evil profile): victim device 192.168.254.2.")
        assert "e0030703.pcap" in syn._plain_headline(s)

    def test_an_initial_and_an_abbreviation_stay_inside(self):
        assert syn.first_sentence("Files were copied by J. Smith at 10:00. Then deleted.") == \
            "Files were copied by J. Smith at 10:00."
        assert syn.first_sentence("approx. 5 files were staged. Then sent.") == \
            "approx. 5 files were staged."

    def test_a_lower_case_continuation_is_not_a_new_sentence(self):
        assert syn.first_sentence("the tool ran. and then it stopped. Next.") == \
            "the tool ran. and then it stopped."

    def test_an_ordinary_stop_still_ends_the_sentence(self):
        assert syn.first_sentence("Dc1.exe was found in the bin. Next line.") == \
            "Dc1.exe was found in the bin."
        assert syn.first_sentence("Logon from 192.168.1.111. Then a logoff.") == \
            "Logon from 192.168.1.111."


class TestCarries:
    """The written answer must carry the headlines' facts: a reply that only
    restates the question and the verdict is the scaffold said worse."""

    def test_a_reply_without_the_headlines_facts_does_not_carry(self):
        assert not syn._carries(
            "Indicators were found. No specific findings, hosts or time span are documented.",
            SCAFFOLD, "What happened?")

    def test_a_reply_naming_a_headline_entity_carries(self):
        assert syn._carries("Ransomware was found on CORP-SRV01.", SCAFFOLD, "What happened?")

    def test_a_reply_that_drops_the_headlines_only_entity_does_not(self):
        assert not syn._carries("Ransomware was found on the file server.", SCAFFOLD, "What happened?")

    def test_one_shared_common_word_is_coincidence_not_content(self):
        scaffold = dict(SCAFFOLD, points=[
            "Security.evtx on PC spans 2015-03-22 14:33:53 to 2015-03-25 15:31:00 (1,193 records)",
            "Nine LNK files in the Recent folders reference the confidential documents"])
        question = "Timeline - solicitation, staging, exfiltration and cover-up, in local time and UTC"
        assert not syn._carries(
            "Indicators were found. No specific hosts, time spans or supporting findings are established.",
            scaffold, question)
        assert syn._carries(
            "Security.evtx on the PC covers 2015-03-22 to 2015-03-25 and nine LNK files reference the documents.",
            scaffold, question)

    def test_words_the_question_itself_uses_do_not_count(self):
        scaffold = dict(SCAFFOLD, points=["System baseline from SYSTEM registry hive"])
        question = "Device and system baseline: operating system and install date"
        assert not syn._carries("Indicators were found in the system baseline.", scaffold, question)
        assert syn._carries("The registry hive gives the baseline.", scaffold, question)

    def test_no_headlines_or_no_facts_beyond_the_question_is_nothing_to_check(self):
        assert syn._carries("Anything.", dict(SCAFFOLD, points=[]), "What happened?")
        assert syn._carries("Indicators were found in the intercepted capture.",
                            dict(SCAFFOLD, points=["Intercepted capture"]),
                            "The intercepted capture - the file the sniffer produced")


class TestSynthesizeAnswerTextFaithfulness:
    def test_a_reply_that_drops_the_headlines_falls_back(self, llm_reply, tmp_path):
        llm_reply["reply"] = _chat_body(
            content="Indicators were found. No specific findings, hosts or time span are documented.")
        out = syn.synthesize_answer_text(tmp_path, "task-1", "What happened?", LEAD_SCAFFOLD)
        assert out == LEAD_SCAFFOLD["text"]

    def test_the_prompt_says_the_headlines_are_the_content(self, llm_reply, tmp_path):
        llm_reply["reply"] = _chat_body(content=GOOD_PROSE)
        syn.synthesize_answer_text(tmp_path, "task-1", "What happened?", LEAD_SCAFFOLD)
        system = llm_reply["body"]["messages"][0]["content"]
        assert "carry each headline's facts" in system
        assert "no relation" in system and "do not repeat" in system


class TestMalwareQuestion:
    """A question about malware or viruses asks about malicious activity and
    is answered by a detection, not by every finding that names a file."""

    Q = "Malware - whether the machine carries viruses."

    def test_a_detection_speaks_to_it(self):
        assert syn.speaks_to(self.Q, "ClamAV detected Win.Trojan.Cain-9 in Abel.dll", strict=True)

    def test_findings_that_merely_name_files_or_tools_do_not(self):
        for s in ("Identity binding: Look@LAN irunin.ini contains REGOWNER=Greg Schardt",
                  "Hacking toolset on Desktop/Tools/: 12 shortcuts to attack tools",
                  "Recycle bin contains 4 deleted files: Dc1.exe, Dc2.exe"):
            assert not syn.speaks_to(self.Q, s, strict=True), s

    def test_a_tool_question_is_still_answered_by_the_tools(self):
        assert syn.speaks_to("Which tools were installed?", "Cain.exe and Ethereal installed", strict=True)

    def test_a_cached_reply_that_fails_the_checks_is_re_asked(self, llm_reply, tmp_path):
        fp = syn.scaffold_fingerprint(LEAD_SCAFFOLD)
        syn._save_cache(tmp_path, {"task-1": {
            "text": f"{LEAD} Indicators were found. No specific findings are documented.",
            "fingerprint": fp}})
        llm_reply["reply"] = _chat_body(content=GOOD_PROSE)
        out = syn.synthesize_answer_text(tmp_path, "task-1", "What happened?", LEAD_SCAFFOLD)
        assert out == f"{LEAD} {GOOD_PROSE}"
        assert syn.cached_answer_text(tmp_path, "task-1", fp) == out


class TestAnswerForTaskScaffold:
    """The answer projection hands the prose pass its own scaffold: the
    headlines, hosts and time span the deterministic text was built from.
    Without them the model was asked to rewrite an empty headline list."""

    GRAPH = {"nodes": {
        "C0001": {"id": "C0001", "kind": "claim", "status": "new", "confidence": "LIKELY",
                  "host": "CORP-SRV01", "temporal_qualifier": "2031-02-04T12:00:00Z",
                  "statement": "Ransomware note dropped on CORP-SRV01 by the svc.backup01 account at 2031-02-04 12:00:00 UTC."},
    }}
    TASK = {"id": "task-0001", "text": "What happened on the file server?", "status": "answered",
            "related_claim_ids": ["C0001"]}

    def test_the_projection_carries_headlines_hosts_and_timespan(self):
        ans = syn.answer_for_task(self.TASK, self.GRAPH)
        assert ans["has_answer"]
        assert ans["points"] and "Ransomware note dropped on CORP-SRV01" in ans["points"][0]
        assert ans["hosts"] == ["CORP-SRV01"]
        assert ans["timespan"]

    def test_the_prose_prompt_names_the_headlines(self):
        ans = syn.answer_for_task(self.TASK, self.GRAPH)
        prompt = syn._answer_user_prompt(self.TASK["text"], ans, "en")
        # One finding: it is the lead, written by the renderer and handed
        # to the model as context only; nothing is left to carry.
        assert "Ransomware note dropped on CORP-SRV01" in prompt
        assert '"first_sentence_already_written": "Ransomware note dropped' in prompt
        assert '"headlines": []' in prompt


class TestHeadlineKeepsTheFacts:
    """A statement written "Topic: the facts" is headed by the facts when
    the label names nothing the facts do not; a label that carries the
    only entity keeps its place; a sentence that fits is untouched."""

    def test_the_facts_after_a_label_colon_lead(self):
        st = ("Network identity of the notebook during the Look@LAN setup: IP address "
              "192.168.1.111, NIC MAC 0010a4933e09 (00-10-A4-93-3E-09) on the Xircom card")
        h = syn.headline(st)
        assert h.startswith("IP address 192.168.1.111") and "Look@LAN" not in h

    def test_a_citation_used_as_a_label_yields_to_the_facts(self):
        st = ("rhino2.log (2004-04-28 21:08 UTC): HTTP download of rhino4.jpg from "
              "137.30.120.40 by the suspect host completed in one session of the capture")
        h = syn.headline(st)
        assert h.startswith("HTTP download of rhino4.jpg") and "137.30.120.40" in h

    def test_a_label_that_carries_the_only_entity_keeps_its_place(self):
        st = ("D:\\Finance share listing of the quarter: the folder holds the quarterly "
              "reports and the budget spreadsheets for every month of the year and more")
        assert syn.headline(st).startswith("D:\\Finance share listing")

    def test_a_short_statement_is_unchanged(self):
        st = "Baseline OS versions: Windows Server 2012 R2 on DC01"
        assert syn.headline(st) == st


class TestRequestKindsAndUmbrellas:
    def test_the_kind_is_read_after_the_lead_label(self):
        assert syn.question_kind("Malware — whether the machine carries viruses.") == "yes_no"
        assert syn.question_kind("Baseline — both operating systems; the server's local time") == "what"
        assert syn.question_kind("Any exfiltration?") == "yes_no"
        assert syn.question_kind("Communication identities — which mail address was used?") == "enumeration"
        assert syn.request_body("**Network** — the delivery IP and the C2 IP.") == "the delivery IP and the C2 IP."
        assert syn.request_body("What happened on the hosts?") == "What happened on the hosts?"

    def test_a_question_before_a_colon_is_not_a_label(self):
        assert syn.question_kind("Is there evidence of lateral movement: yes or no?") == "yes_no"
        assert syn.question_kind("Which accounts were used: local or domain?") == "enumeration"
        assert syn.question_kind("Wurden Daten gestohlen: ja oder nein?", "de") == "yes_no"
        assert syn.request_body("Is there evidence of lateral movement: yes or no?").startswith("Is there")

    def test_an_umbrella_names_nothing_after_its_lead(self):
        assert syn.is_general_question("What happened on the Hosts?")
        assert syn.is_general_question("Summarize the incident")
        assert not syn.is_general_question(
            "Data theft timeline — the sauce file and the other sensitive files, plus last adversary contact.")
        assert not syn.is_general_question(
            "Timeline — solicitation → planning → staging → exfiltration → cover-up, in system-local time AND UTC")
        assert not syn.is_general_question(
            "Activity reconstruction & timeline — use the keylogger artefacts and file timestamps to bound the activity window")


class TestVerdictByKind:
    DIARY = {"id": "C1", "kind": "claim", "status": "new", "confidence": "CONFIRMED", "host": "RHINOUSB",
             "statement": "Diary carved from the USB key contains the anti-forensics narrative."}
    FTP = {"id": "C2", "kind": "claim", "status": "new", "confidence": "LIKELY", "host": "",
           "statement": "FTP upload of rhino images to the cook server appears in the network capture."}
    SAME = {"id": "C3", "kind": "claim", "status": "new", "confidence": "CONFIRMED", "host": "",
            "statement": ("rhino1.jpg carved from the USB key is identical to the rhino1.jpg uploaded in "
                          "the FTP session of the network capture (same MD5 sum).")}
    Q_LINK = "Cross-evidence link — prove the connection between USB content and network traffic."

    def test_a_relation_request_is_not_established_by_findings_that_state_no_link(self):
        a = syn.synthesize_answer(self.Q_LINK, [self.DIARY, self.FTP])
        assert a["verdict"].startswith("Not established")
        assert a["text"].startswith("Not established") and "Related:" in a["text"]
        assert a["lead"].startswith("Not established")

    def test_a_relation_request_is_led_by_a_finding_that_states_the_link(self):
        a = syn.synthesize_answer(self.Q_LINK, [self.DIARY, self.FTP, self.SAME])
        assert a["verdict"] == "Lead finding"
        assert "identical" in a["lead"] and "rhino1.jpg" in a["lead"]

    def test_a_conclusion_without_the_relation_does_not_answer_a_relation_request(self):
        concl = dict(self.DIARY, id="N1", kind="conclusion",
                     statement="The USB key and the captures belong to the same suspect's activity.")
        a = syn.synthesize_answer(self.Q_LINK, [concl, self.FTP])
        assert a["verdict"].startswith("Not established")

    def test_a_value_request_is_led_by_the_direct_finding_without_a_completeness_word(self):
        net = {"id": "C4", "kind": "claim", "status": "new", "confidence": "LIKELY", "host": "DC01",
               "statement": "Network: delivery IP is 194.61.24.102 (external, attacker host 'kali'); C2 IP is 10.90.90.90"}
        a = syn.synthesize_answer("Network — the delivery IP and the C2 IP.", [net])
        assert a["verdict"] == "Lead finding" and "194.61.24.102" in a["lead"]
        assert "Indicators found" not in a["text"] and "Answered" not in a["text"]
        other = {"id": "C5", "kind": "claim", "status": "new", "confidence": "LIKELY", "host": "DC01",
                 "statement": "A scheduled task named updater persisted the payload on the server."}
        b = syn.synthesize_answer("Network — the delivery IP and the C2 IP.", [other])
        assert b["verdict"].startswith("Not established")

    def test_a_yes_no_detection_question_keeps_its_verdicts(self):
        a = syn.synthesize_answer("Was the domain controller compromised?", [{
            "id": "C6", "kind": "claim", "status": "new", "confidence": "CONFIRMED", "host": "DC01",
            "statement": "DC01 was compromised through RDP brute force from 194.61.24.102."}])
        assert a["verdict"] == "Indicators found" and a["text"].startswith("Yes")


class TestAddsRelation:
    HEADS = ["rhino1.jpg carved from the USB key", "rhino1.jpg uploaded in the FTP session"]

    def test_a_relation_the_headlines_do_not_state_is_detected(self):
        assert syn._adds_relation("The two files are identical.", self.HEADS)
        assert syn._adds_relation("The carving proves the upload came from the key.", self.HEADS)
        assert syn._adds_relation("Daher stammt die Datei vom USB-Stick.", self.HEADS)

    def test_facts_stated_plainly_pass(self):
        assert not syn._adds_relation("rhino1.jpg was carved from the USB key and uploaded in the FTP session.", self.HEADS)

    def test_a_relation_a_headline_states_may_be_repeated(self):
        heads = ["rhino1.jpg on the key is identical to the uploaded rhino1.jpg"]
        assert not syn._adds_relation("The two copies of rhino1.jpg are identical.", heads)


class TestConclusionLead:
    GRAPH = {"nodes": {
        "C0001": {"id": "C0001", "kind": "claim", "status": "new", "confidence": "LIKELY",
                  "host": "LONEWOLF", "statement": "Planning.docx and the presentation were opened from the Documents folder."},
        "N0001": {"id": "N0001", "kind": "conclusion", "status": "new", "confidence": "LIKELY",
                  "host": "LONEWOLF",
                  "statement": ("The planning material comprises Planning.docx, the manifesto and the presentation. "
                                "They were edited over three days.")},
    }}

    def test_the_conclusions_first_sentence_is_the_lead(self):
        task = {"id": "task-0001", "text": "Intent — locate the planning material (manifesto, plan documents, presentation).",
                "status": "answered", "related_claim_ids": ["C0001", "N0001"]}
        ans = syn.answer_for_task(task, self.GRAPH, {})
        assert ans["conclusion_lead"] is True
        assert ans["lead"] == "The planning material comprises Planning.docx, the manifesto and the presentation."
        assert ans["text"].startswith(ans["lead"])


class TestShortenedPoints:
    """A point the answer had to shorten says so with an ellipsis; a
    fragment never ends in a full stop that makes it read as whole."""

    UPLOAD = ("FTP upload session in capture.pcap: 10.0.0.9 uploaded alpha1.jpg (65703 bytes), "
              "alpha3.jpg (193797 bytes), and bundle.zip (230566 bytes) to 10.0.0.40:21 using "
              "credentials USER jdoe / PASS example123 (2004-04-26 22:21-22:26 UTC)")

    def test_a_cut_point_ends_in_an_ellipsis(self):
        point = syn._plain_headline(self.UPLOAD)
        assert point.endswith("…") and not point.endswith("/…")

    def test_a_separator_left_by_a_cut_is_dropped(self):
        point = syn._plain_headline("Logged in with USER jdoe / (the password is in a later record")
        assert point == "Logged in with USER jdoe…"

    def test_a_point_that_fits_is_a_sentence(self):
        assert syn._plain_headline("Eraser was installed on HOST-A.") == "Eraser was installed on HOST-A"

    def test_the_answer_never_stacks_a_stop_on_a_cut(self):
        claim = {"id": "C0001", "confidence": "LIKELY", "status": "new", "statement": self.UPLOAD}
        short = {"id": "C0002", "confidence": "LIKELY", "status": "new",
                 "statement": "HTTP downloads of alpha4.jpg from 10.0.0.37 followed."}
        a = syn.synthesize_answer("Which file transfers appear in the network traces?", [claim, short])
        assert "…." not in a["text"] and "/." not in a["text"]
        assert a["lead"].endswith(("…", "."))


class TestAnswerPointsKeepTheFacts:
    """An answer point stands for what the finding says: a long "label:
    facts" lead keeps its facts (a finding's heading may still be the
    label), and a cut inside a parenthetical that only a label precedes
    keeps the parenthetical."""

    LABELLED = ("Categories of the copied material: design documents (slide decks), progress "
                "reports (text documents), proposals (text documents), and pricing decisions "
                "(spreadsheets). The four categories follow from the file names on the key.")
    PHASES = ("Phases: contact (an initial mail from third.party@example.com to "
              "jane.doe@example.com, recovered from the mailbox export of the workstation), "
              "planning (two replies from the subject), staging (copies to the key).")

    def test_a_labelled_lead_keeps_its_facts(self):
        point = syn._plain_headline(self.LABELLED)
        assert point.startswith("Categories of the copied material: design documents")
        assert point.endswith("…")

    def test_the_heading_of_the_same_finding_is_still_its_label(self):
        assert syn.headline(self.LABELLED) == "Categories of the copied material"

    def test_a_parenthetical_after_a_bare_label_is_kept(self):
        point = syn._plain_headline(self.PHASES)
        assert point.startswith("Contact (an initial mail from third.party@example.com")
        assert point.endswith("…)") and "…)…" not in point

    def test_a_parenthetical_after_a_statement_is_still_cut(self):
        point = syn._plain_headline("Logged in with USER jdoe / (the password is in a later record")
        assert point == "Logged in with USER jdoe…"

    def test_a_gap_listed_under_an_answer_names_what_went_unexamined(self):
        a = syn.synthesize_answer("Any exfiltration?", [GAP_CLAIM])
        assert any("(1) CORP-DC01 System and Application EVTX" in g for g in a["gaps"])
