"""What the CONFIRMED tier tells the model. The evaluate gate's refusal says
that no review holds these exact words and names a SUPPORTED review of a
longer or shorter form of them after its own repair path; it never names a
reworded statement's review or a sibling finding's. The record_finding
schema says what CONFIRMED needs and that a missing link stops the in-call
evaluation. Invented case data only (CORP-WS01, jane.doe, 203.0.113.x,
2031)."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog
from tools._gates import GateContext
from tools._gates import confirmed_requires_supported_evaluate as evaluate_gate

A = ("The memo README_RESTORE.txt on CORP-WS01 says the share \\\\FILESRV\\projects was archived to "
     "backup.example.com on 2031-03-04 at 09:12.")
HEDGE = " This is what the memo asserts; no claim is made about other shares."
SIBLING = "The account jane.doe logged on to CORP-WS01 from 203.0.113.7 at 2031-03-04T08:55Z."
OTHER_ON_HOST = "CORP-WS01 ran C:\\ProgramData\\upd\\backup.exe at 2031-03-04T09:20Z."


@pytest.fixture(autouse=True)
def _no_side_helpers():
    with patch("tools.misc.tool_program", side_effect=lambda name, *rest: f"/usr/local/bin/{name}"), \
            patch("tools.misc._confirmed_presence", lambda *a, **k: None):
        yield


def _log(tmp_path):
    lg = ExecutionLog()
    lg.configure("CASE-A", str(tmp_path / "trace.json"), save_session=False)
    lg.record_dair_call("Triage", "", False, "", "", "stay", "")
    return lg


def _review(lg, words: str, verdict: str = "SUPPORTED", **inputs) -> int:
    return lg.record_reason_call(
        "reason_evaluate_finding", True, f"VERDICT: {verdict}", {},
        inputs={"user_message": f"FINDING:\n{words}\n\nSUPPORTING EVIDENCE:\nnotes.txt read in full", **inputs})


def _ctx(lg, desc: str, evidence: str = "", cited=()) -> GateContext:
    return GateContext(description=desc, confidence="CONFIRMED", tier="CONFIRMED", source="probe",
                       linked_call_id=0, tested_hypothesis_id="", log=lg, idx=lg.index(),
                       window=lg.last_n_window(30), reason_window=lg.gate_window(30),
                       input_call_ids=list(cited), analyst_call_ids=list(cited), supporting_evidence=evidence)


class TestTheReviewOfAnotherForm:
    @pytest.mark.parametrize("reviewed, recorded", [(A, A + HEDGE), (A + HEDGE, A)])
    def test_a_supported_review_of_a_longer_or_shorter_form_is_named_after_the_cheap_path(
            self, tmp_path, reviewed, recorded):
        lg = _log(tmp_path)
        cid = _review(lg, reviewed)
        err = evaluate_gate.check(_ctx(lg, recorded))["error"]
        assert "none for this finding" not in err
        assert "these exact words" in err and f"Call {cid} reviewed (SUPPORTED)" in err
        # JSON-quoted, as every analyst or evidence text in a block Atlas writes.
        assert json.dumps(" ".join(reviewed.split()), ensure_ascii=False)[:60] in err
        assert err.index("LIKELY") < err.index(f"Call {cid}")

    def test_a_negated_statement_is_not_steered_to_the_reviewed_claim(self, tmp_path):
        """"No row shows that A" holds A: the review of A is named, but the
        text leaves it to the analyst whether A is what was meant, and asks
        for an evaluation of these words first."""
        lg = _log(tmp_path)
        _review(lg, A)
        err = evaluate_gate.check(_ctx(lg, "No row shows that " + A[0].lower() + A[1:]))["error"]
        assert "reviewed (SUPPORTED)" in err
        assert "record those words as reviewed" not in err
        assert err.index("evaluate these words") < err.index("record the reviewed words if that is what you mean")

    def test_a_short_claim_inside_a_long_finding_or_a_part_word_is_not_a_form_of_it(self, tmp_path):
        lg = _log(tmp_path)
        _review(lg, "CORP-WS01 is online.")
        _review(lg, "WS01 ran backup.exe at 2031-03-04T09:20Z.")
        long_finding = ("CORP-WS01 is online. It ran C:\\ProgramData\\upd\\backup.exe at 2031-03-04T09:20Z, which "
                        "wrote staged.7z (48,512 bytes) and sent it to backup.example.com over 443.")
        assert "reviewed (SUPPORTED)" not in evaluate_gate.check(_ctx(lg, long_finding))["error"]
        assert "reviewed (SUPPORTED)" not in evaluate_gate.check(
            _ctx(lg, "CORP-WS01 ran backup.exe at 2031-03-04T09:20Z."))["error"]

    def test_a_words_edge_punctuation_does_not_break_the_run(self):
        """A statement that ends at "09:12." is a shorter form of the one
        that goes on "09:12, and names ticket 4471."."""
        short = "the memo says the share was archived to backup.example.com on 2031-03-04 at 09:12."
        assert evaluate_gate._other_form(short, short[:-1] + ", and names ticket 4471.")

    def test_the_form_share_is_one_half_of_the_longer_statement(self):
        assert evaluate_gate._FORM_SHARE == 0.5
        assert evaluate_gate._other_form("a b c d", "b c")
        assert not evaluate_gate._other_form("a b c d e", "b c")
        assert not evaluate_gate._other_form("a b c d", "a b c d")

    def test_a_sibling_review_on_the_same_host_is_never_named(self, tmp_path):
        lg = _log(tmp_path)
        _review(lg, SIBLING)
        err = evaluate_gate.check(_ctx(lg, OTHER_ON_HOST))["error"]
        assert "reviewed (SUPPORTED)" not in err and "jane.doe" not in err
        assert "these exact words" in err

    def test_a_reworded_statement_names_no_review(self, tmp_path):
        """The reword class is not resolved here: no review is named, the
        text says a review counts only for the words it reviewed."""
        lg = _log(tmp_path)
        _review(lg, A)
        err = evaluate_gate.check(_ctx(lg, A.replace("says", "states").replace("on CORP-WS01", "from CORP-WS01")))["error"]
        assert "reviewed (SUPPORTED)" not in err
        assert "a review counts only for the words it reviewed" in err

    @pytest.mark.parametrize("verdict", ["CHALLENGED", "UNCERTAIN"])
    def test_a_review_that_did_not_support_the_other_form_is_not_named(self, tmp_path, verdict):
        lg = _log(tmp_path)
        _review(lg, A, verdict)
        assert "reviewed (SUPPORTED)" not in evaluate_gate.check(_ctx(lg, A + HEDGE))["error"]

    def test_the_stale_auto_evaluation_path_names_no_other_form(self, tmp_path, monkeypatch):
        """A statement's own auto-evaluation, judged again on new rows, is a
        review of these words: no longer or shorter form is named there."""
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        lg = _log(tmp_path)
        _review(lg, A + HEDGE)
        _review(lg, A, "CHALLENGED", auto=True)
        hit = evaluate_gate.check(_ctx(lg, A, evidence="notes.txt line 4: archived to backup.example.com"))
        assert hit.get("missing_check") == "reason_evaluate_finding"
        assert "reviewed (SUPPORTED)" not in hit["error"]


class TestTheRefusalAsTheModelReadsIt:
    def test_the_joined_error_keeps_the_link_and_the_cheap_path_after_the_cut(self, tmp_path, monkeypatch):
        """Link and evaluation missing: the link gate is the headline, the
        evaluate gate's text rides in the joined error cut at 400
        characters; the cheap path survives the cut, the quoted form is
        last."""
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        from tools.misc import record_finding
        lg = _log(tmp_path)
        tid = lg.record_tool_call("<py>:strings_read_text", True, False, 0, 0,
                                  evidence_ref="analysis/extracted/CORP-WS01/notes.txt",
                                  stdout_excerpt="archived to backup.example.com on 2031-03-04 at 09:12")
        _review(lg, A)
        with patch("core.execution_log.log", lg):
            r = record_finding(A + HEDGE, "CONFIRMED", "strings", input_call_ids=[tid],
                               supporting_evidence="notes.txt: archived to backup.example.com")
        assert r["success"] is False and r["detail_gate"] == "confirmed_requires_linked_call_id"
        (entry,) = [o for o in r["also_refused_by"] if o["detail_gate"] == "confirmed_requires_supported_evaluate"]
        assert "Reviewed words:" in entry["error"]          # the review is named on the entry itself
        fragment = r["error"].split("[confirmed_requires_supported_evaluate] ", 1)[1].split(" | [", 1)[0]
        # Cut at a sentence end: the cheap path whole, no half-quoted review.
        assert fragment.endswith("or record it as SUSPECTED/LIKELY, which needs no evaluation.")
        assert '"' not in fragment and "Call " not in fragment.split("first, then", 1)[1]

    def test_every_other_gate_keeps_its_first_400_characters_in_the_joined_error(self, tmp_path, monkeypatch):
        """Only the evaluate gate's entry is cut at a sentence end; another
        gate's repair instruction sits in its first 400 characters and is
        kept byte for byte (confidence_and_citation: the values to add)."""
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        from tools.misc import record_finding
        lg = _log(tmp_path)
        tid = lg.record_tool_call("<py>:strings_read_text", True, False, 0, 0,
                                  evidence_ref="analysis/extracted/CORP-WS01/notes.txt",
                                  stdout_excerpt="archived to backup.example.com")
        temp = "C:\\Users\\jane.doe\\AppData\\Local\\Temp\\"
        desc = (f"CORP-WS01 wrote {temp}staged_a.7z, {temp}staged_b.7z, {temp}staged_c.7z and "
                f"{temp}staged_d.7z and sent them to backup.example.com.")
        with patch("core.execution_log.log", lg):
            r = record_finding(desc, "CONFIRMED", "strings", input_call_ids=[tid],
                               supporting_evidence="notes.txt: archived to backup.example.com")
        (entry,) = [o for o in r["also_refused_by"] if o["detail_gate"] == "confidence_and_citation"]
        assert len(entry["error"]) > 400
        fragment = r["error"].split("[confidence_and_citation] ", 1)[1].split(" | [", 1)[0]
        assert fragment == entry["error"][:400]

    def test_a_missing_link_refuses_and_stops_the_in_call_evaluation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        from tools.misc import record_finding
        lg = _log(tmp_path)
        tid = lg.record_tool_call("vol.psscan", True, False, 0, 0, stdout_excerpt="PID 5024 svchost.exe")
        calls = []
        with patch("core.execution_log.log", lg), \
                patch("tools.misc._auto_evaluate", lambda *a, **k: calls.append(a) or {"verdict": "SUPPORTED"}):
            r = record_finding("Process 5024 is present in the memory image", "CONFIRMED", "vol.psscan",
                               input_call_ids=[tid], supporting_evidence="vol.psscan: PID 5024 svchost.exe")
        assert r["success"] is False and r["detail_gate"] == "confirmed_requires_linked_call_id"
        assert calls == []

    def test_the_in_call_evaluation_still_runs_on_the_new_text(self, tmp_path, monkeypatch):
        """The auto-evaluation keys on the refusal's missing_check: the new
        wording, a longer form's review named in it, still lets it run."""
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        from tools.misc import record_finding
        lg = _log(tmp_path)
        tid = lg.record_tool_call("<py>:strings_read_text", True, False, 0, 0,
                                  evidence_ref="analysis/extracted/CORP-WS01/notes.txt",
                                  stdout_excerpt="archived to backup.example.com on 2031-03-04 at 09:12")
        _review(lg, A)
        calls = []
        with patch("core.execution_log.log", lg), \
                patch("tools.misc._auto_evaluate", lambda *a, **k: calls.append(a) or {"verdict": "SUPPORTED"}):
            record_finding(A + HEDGE, "CONFIRMED", "strings", linked_call_id=tid, input_call_ids=[tid],
                           supporting_evidence="notes.txt: archived to backup.example.com")
        assert len(calls) == 1


class TestTheSchema:
    def _params(self):
        import asyncio
        from core.tool_text import model_description
        from tools.misc import mcp
        t = asyncio.run(mcp.get_tool("record_finding"))
        return model_description(t.description or "", dict(t.parameters))[1]["properties"]

    def test_confidence_states_what_confirmed_needs_and_what_is_lowered(self):
        conf = self._params()["confidence"]["description"]
        assert "linked_call_id" in conf and "these exact words" in conf
        assert "missing linked_call_id is refused and stops that evaluation" in conf
        assert "fails only because the tier is too strong" not in conf
        assert "one tier lower" in conf

    def test_linked_call_id_says_it_is_required_for_confirmed(self):
        assert "REQUIRED for CONFIRMED" in self._params()["linked_call_id"]["description"]
