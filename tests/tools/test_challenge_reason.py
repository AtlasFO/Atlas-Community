"""The evaluator's reason, by the sections Atlas's own evaluation prompt
prescribes, in the forms small models write them. Invented answers."""
from __future__ import annotations

import pytest

from core.text_bounds import cut
from tools.reasoning import challenge_reason, evaluation_sections

LONG_SUPPORT = "The row shows a network connection to 203.0.113.60 port 443 at 2031-03-10 14:05:30. " * 8


def test_the_reason_comes_first_and_the_supported_part_is_left_out():
    a = (f"VERDICT: CHALLENGED\n1. EVIDENCE SUPPORT — {LONG_SUPPORT}\n2. CONTRADICTING EVIDENCE — Timestamp "
         "mismatch: the finding states 14:25:03, the row 14:05:30.\n3. ALTERNATIVE EXPLANATIONS — None.\n"
         "4. HALLUCINATION CHECK — None\n5. FACT-CHECK — None.\n6. ADDITIONAL INVESTIGATION — read later rows.\n"
         "7. VERDICT: CHALLENGED — the time does not match the cited row.")
    r = challenge_reason(a, "CHALLENGED")
    assert r.startswith("the time does not match the cited row.")
    assert "contradicting evidence: Timestamp mismatch" in r and "network connection to" not in r
    assert "None" not in r and "alternative explanations" not in r and len(r) <= 600


@pytest.mark.parametrize("answer", [
    "**VERDICT: CHALLENGED**\n**1. EVIDENCE SUPPORT** row X.\n**2. CONTRADICTING EVIDENCE**: the row is another host's.",
    "## VERDICT: CHALLENGED\n## 1) Evidence Support\nrow X\n## 2) Contradicting Evidence\nthe row is another host's.",
    "VERDICT: CHALLENGED 1 - Evidence Support: row X 2 - Contradicting Evidence: the row is another host's.",
    "VERDICT: CHALLENGED 1. Evidence Support: row X. 2. Contradicting evidence — the row is another host's.",
])
def test_every_heading_form_and_a_single_line_answer_parse(answer):
    assert evaluation_sections(answer)[2].startswith("the row is another host's")
    assert challenge_reason(answer, "CHALLENGED").startswith("contradicting evidence: the row is another host's")


def test_the_fact_check_and_for_uncertain_the_alternatives_are_kept():
    a = ("VERDICT: UNCERTAIN 1. EVIDENCE SUPPORT row X. 2. CONTRADICTING EVIDENCE None. 3. ALTERNATIVE "
         "EXPLANATIONS A nightly job explains the logon. 5. FACT-CHECK Installed is not run. 7. VERDICT: UNCERTAIN - "
         "the act is not shown.")
    r = challenge_reason(a, "UNCERTAIN")
    assert r == ("the act is not shown. | alternative explanations: A nightly job explains the logon. | "
                 "fact-check: Installed is not run.")
    assert "alternative explanations" not in challenge_reason(a, "CHALLENGED")


def test_the_first_line_verdict_is_no_section_and_a_free_answer_gives_its_head():
    assert 7 not in evaluation_sections("VERDICT: CHALLENGED\nThe statement overreaches the rows.")
    assert challenge_reason("VERDICT: CHALLENGED The statement overreaches the rows.", "CHALLENGED") == \
        "The statement overreaches the rows."


def test_the_one_cut_never_ends_inside_a_word():
    text = "word " * 200
    out = cut(text, 101)
    assert out.endswith("…") and out[:-1].split()[-1] == "word" and len(out) <= 101


@pytest.mark.parametrize("answer, sec2, has7", [
    ("1. EVIDENCE SUPPORT: as noted, see section 2 contradicting evidence below and item 7 verdict later. "
     "2. CONTRADICTING EVIDENCE: real reason here. 7. VERDICT: CHALLENGED - final.", "real reason here.", True),
    ("1. EVIDENCE SUPPORT: row X. 2. CONTRADICTING EVIDENCE: event 4624 at 10:02 vs 7 VERDICT not shown "
     "anywhere.", "event 4624 at 10:02 vs 7 VERDICT not shown anywhere.", False),
    ("1. EVIDENCE SUPPORT: row X. 2. CONTRADICTING EVIDENCE: 3 alternative explanation exist for the row. "
     "4. HALLUCINATION CHECK: None.", "3 alternative explanation exist for the row.", False),
])
def test_prose_that_names_a_section_is_no_heading(answer, sec2, has7):
    secs = evaluation_sections(answer)
    assert secs[2] == sec2 and (7 in secs) == has7 and 3 not in secs
    if has7:
        assert secs[7].endswith("final.")


@pytest.mark.parametrize("answer", [
    "VERDICT: CHALLENGED\n1. EVIDENCE SUPPORT: row X; see 7. VERDICT below.\n2. CONTRADICTING EVIDENCE: the row is "
    "another host's.\n7. VERDICT: CHALLENGED - wrong host.",
    "VERDICT: CHALLENGED\n1. EVIDENCE SUPPORT: row X, item 7 verdict: depends.\n2. CONTRADICTING EVIDENCE: the row is "
    "another host's.\n7. VERDICT: CHALLENGED - wrong host.",
])
def test_a_delimited_mid_line_reference_never_cuts_a_line_start_section(answer):
    secs = evaluation_sections(answer)
    assert secs[2] == "the row is another host's." and secs[7].endswith("wrong host.")
    assert challenge_reason(answer, "CHALLENGED") == "wrong host. | contradicting evidence: the row is another host's."


def test_a_verdict_first_answer_keeps_every_section():
    a = ("7. VERDICT: CHALLENGED - capability only.\n1. EVIDENCE SUPPORT: the service is installed.\n"
         "5. FACT-CHECK: installed is not run.\n6. ADDITIONAL INVESTIGATION: read the service's start events.")
    secs = evaluation_sections(a)
    assert set(secs) == {1, 5, 6, 7} and secs[5] == "installed is not run."
    assert challenge_reason(a, "CHALLENGED") == "capability only. | fact-check: installed is not run."


UNNUMBERED = ("VERDICT: CHALLENGED\n\nEVIDENCE SUPPORT\nThe row shows svc_kit.exe starting at 2031-03-10 14:02:10.\n\n"
              "CONTRADICTING / WEAKENING EVIDENCE\n1. No row shows the file arriving.\n2. The user is jane.doe, "
              "not an attacker.\n\nFACT-CHECK\nNone.\n\nVERDICT RATIONALE\nThe start is shown; the staging is not.")


def test_headings_without_numbers_each_alone_on_a_line_are_read():
    secs = evaluation_sections(UNNUMBERED)
    assert set(secs) == {1, 2, 5, 7} and secs[2].startswith("1. No row shows the file arriving.")
    assert challenge_reason(UNNUMBERED, "CHALLENGED") == (
        "The start is shown; the staging is not. | contradicting evidence: 1. No row shows the file arriving. "
        "2. The user is jane.doe, not an attacker.")


@pytest.mark.parametrize("prose", ["CONTRADICTING EVIDENCE owner logs daily", "Verdict depends on context",
                                   "Evidence support is thin here"])
def test_a_prose_line_that_starts_with_a_section_name_is_no_heading(prose):
    a = (f"VERDICT: CHALLENGED\nEVIDENCE SUPPORT\nThe row shows the owner.\n{prose}\nCONTRADICTING EVIDENCE\n"
         "the owner was away.\nVERDICT\nThe rows show the owner, so the attacker claim is unsupported.")
    secs = evaluation_sections(a)
    assert secs[1] == f"The row shows the owner. {prose}"
    assert secs[7] == "The rows show the owner, so the attacker claim is unsupported."


def test_a_bare_name_in_any_case_is_a_heading_and_the_verdict_line_is_not():
    a = "VERDICT: CHALLENGED\n## Evidence support\nrow 4.\n## Contradicting evidence:\nanother host's row.\n## Verdict\nwrong host."
    assert evaluation_sections(a) == {1: "row 4.", 2: "another host's row.", 7: "wrong host."}


def test_numbered_and_unnumbered_headings_mix_in_text_order():
    a = ("VERDICT: CHALLENGED\nEVIDENCE SUPPORT\nrow 4.\nCONTRADICTING EVIDENCE\nanother host's row.\n"
         "7. VERDICT: CHALLENGED - wrong host.")
    secs = evaluation_sections(a)
    assert secs[2] == "another host's row." and secs[7] == "CHALLENGED - wrong host."
    assert challenge_reason(a, "CHALLENGED") == "wrong host. | contradicting evidence: another host's row."


def test_a_lone_name_inside_a_numbered_answer_cuts_nothing():
    a = ("VERDICT: CHALLENGED\n1. EVIDENCE SUPPORT: row 4.\n2. CONTRADICTING EVIDENCE: the row is another host's.\n"
         "FACT-CHECK\nstill section 2.\n7. VERDICT: CHALLENGED - wrong host.")
    assert evaluation_sections(a)[2] == "the row is another host's. FACT-CHECK still section 2."


@pytest.mark.parametrize("seven, reason", [
    ("7. VERDICT: SUPPORTED / CHALLENGED / UNCERTAIN\n- VERDICT: CHALLENGED - the time is not the row's.",
     "the time is not the row's."),
    ("7. VERDICT: CHALLENGED or UNCERTAIN depending on whether the owner was away.",
     "or UNCERTAIN depending on whether the owner was away."),
])
def test_only_the_prompts_verdict_list_is_stripped_as_an_echo(seven, reason):
    a = f"VERDICT: CHALLENGED\n1. EVIDENCE SUPPORT: row 4.\n2. CONTRADICTING EVIDENCE: None.\n{seven}"
    assert challenge_reason(a, "CHALLENGED") == reason


# -- the prompt's own words and a heading's continuation leave the reason -------------------

def test_the_prompts_placeholder_a_rationale_heading_and_a_heading_tail_leave_the_reason():
    from tools.reasoning import _EVALUATE_SYS, _PLACEHOLDER
    assert _PLACEHOLDER and _PLACEHOLDER in _EVALUATE_SYS                 # read from the prompt itself
    echoed = ("VERDICT: CHALLENGED\n1. EVIDENCE SUPPORT: row shows a logon.\n"
              "2. CONTRADICTING EVIDENCE / WEAKENING FACTS: the row names jane.doe, not an attacker.\n"
              "7. VERDICT: SUPPORTED / CHALLENGED / UNCERTAIN — one-line rationale. CHALLENGED because the "
              "attribution is not shown.")
    assert challenge_reason(echoed, "CHALLENGED") == ("because the attribution is not shown. | contradicting "
                                                      "evidence: the row names jane.doe, not an attacker.")
    for heading in ("7. VERDICT RATIONALE: CHALLENGED because the row shows no execution.",
                    "7. VERDICT: rationale CHALLENGED because the row shows no execution.",
                    "7. VERDICT: Rationale - CHALLENGED because the row shows no execution."):
        assert challenge_reason("VERDICT: CHALLENGED\n" + heading, "CHALLENGED") == \
            "because the row shows no execution."


def test_a_rationale_that_opens_with_capitals_or_names_rationale_inside_keeps_its_words():
    a = ("VERDICT: CHALLENGED\n2. CONTRADICTING EVIDENCE: AND SMB SESSIONS from CORP-WS02 show the copy came first.\n"
         "7. VERDICT: CHALLENGED - SMB AND RDP both reached the host; the rationale of the finding is weak.")
    assert challenge_reason(a, "CHALLENGED") == ("SMB AND RDP both reached the host; the rationale of the finding is "
                                                 "weak. | contradicting evidence: AND SMB SESSIONS from CORP-WS02 "
                                                 "show the copy came first.")
