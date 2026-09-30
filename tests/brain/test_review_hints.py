"""Staging-time junk pre-filter: review_hints on memory candidates."""

import pytest

from core.brain import capture, frontmatter, review_candidates

JUNK = [
    # (text, expected signal category)
    ("The final report is due Friday — finish the timeline section.",
     "deadline"),
    ("Extraction deadline moved to next week.", "deadline"),
    ("Get the coverage report done by Wednesday.", "deadline"),
    ("On the next run, re-check the USN journal for the gap.",
     "next_run_todo"),
    ("Confirm with the operator whether a second disk image exists.",
     "next_run_todo"),
    ("Follow up on the outstanding registry questions.", "next_run_todo"),
    ("Pick up the new E01 from the evidence locker.", "case_logistics"),
    # two weak signals co-occurring
    ("Re-run the timeline once the D: partition image arrives.",
     "drive_letter"),
    ("Check UserAssist on WIN-4XZK9 for execution artifacts.",
     "specific_host"),
]

DURABLE = [
    # the conservative bar: a genuine gotcha with a single weak cue stays clean
    "Re-run with a narrower, more specific pattern when strings_grep "
    "output is truncated.",
    "Volatility needs the Win11 symbol pack flag on modern memory images.",
    "Run coverage.coverage_report before the Report phase so TTPs get mapped.",
    "A truncated tool result is incomplete — re-check with a targeted "
    "sub-query before recording a negative finding.",
    "MFTECmd timestomp checks must compare $STANDARD_INFORMATION against "
    "$FILE_NAME timestamps.",
    "Prefer structured extractors over keyword search for artifacts with "
    "a known schema.",
]


@pytest.mark.parametrize("text,category", JUNK)
def test_junk_text_is_flagged(text, category):
    hints = capture._review_hints(text)
    assert hints["likely_case_specific"] is True
    assert any(s.startswith(category) for s in hints["signals"])


@pytest.mark.parametrize("text", DURABLE)
def test_durable_lesson_is_not_flagged(text):
    assert capture._review_hints(text)["likely_case_specific"] is False


def test_single_weak_signal_does_not_flag():
    hints = capture._review_hints(
        "Re-run plaso with the filter file when the full timeline times out.")
    assert hints["likely_case_specific"] is False
    assert any(s.startswith("rerun_recheck") for s in hints["signals"])


REVIEW = """# Run Review — TESTCASE

VERDICT: ACCEPTABLE

## Recommendations

- Follow up with the operator once the E01 is in.
- Volatility needs the Win11 symbol pack flag on modern memory images.
"""


@pytest.fixture
def case(tmp_path):
    case_dir = tmp_path / "case"
    (case_dir / "analysis").mkdir(parents=True)
    (case_dir / "reports").mkdir()
    return case_dir


def test_case_specific_workflow_candidate_is_dropped(brain, case):
    # The pre-filter is now a GATE for run-residue types: the case-specific
    # "follow up once the E01 is in" workflow bullet is dropped, the durable
    # Volatility tool gotcha stays. (Was decision-support-only; the 88%-noise
    # intake motivated the hard drop.)
    result = capture.capture_run(case, "TESTCASE", "q", REVIEW, "ACCEPTABLE")
    assert result["candidates"] == 1
    assert result["dropped_case_residue"] == 1
    titles = []
    for p in (brain / "inbox/memory-candidates").glob("*.md"):
        meta, _, _ = frontmatter.parse(p.read_text())
        titles.append(meta["title"])
    assert titles == ["Volatility needs the Win11 symbol pack flag on modern "
                      "memory images."]
    assert not any("Follow up" in t for t in titles)


def test_technique_insight_not_dropped_on_case_signal_alone(brain, case):
    # Safety valve: technique_insight/issue can legitimately cite an
    # IP/hostname/artifact and must NOT be dropped on a case-specific signal —
    # only workflow / tool_gotcha run-residue is. "artifact" routes to
    # technique_insight; the E01/next_run_todo signal must not drop it.
    review = ("# Run Review — TESTCASE\n\nVERDICT: ACCEPTABLE\n\n"
              "## Recommendations\n\n"
              "- Follow up on the artifact once the E01 is in.\n")
    result = capture.capture_run(case, "TESTCASE", "q", review, "ACCEPTABLE")
    assert result["candidates"] == 1
    assert result["dropped_case_residue"] == 0


def test_review_listing_exposes_hints_on_surviving_candidates(brain, case):
    # Dropped run-residue no longer appears; the surviving clean candidate is
    # listed with empty hints.
    capture.capture_run(case, "TESTCASE", "q", REVIEW, "ACCEPTABLE")
    items = review_candidates.list_candidates()
    assert len(items) == 1
    assert not items[0]["likely_case_specific"]
    assert items[0]["hints"] == ""


def test_review_listing_tolerates_candidates_without_hints(brain, case):
    capture.capture_run(case, "TESTCASE", "q", REVIEW, "ACCEPTABLE")
    for p in (brain / "inbox/memory-candidates").glob("*.md"):
        meta, body, _ = frontmatter.parse(p.read_text())
        meta.pop("review_hints", None)  # candidate staged by an older capture
        p.write_text(frontmatter.serialize(meta, body))
    items = review_candidates.list_candidates()
    assert all(i["hints"] == "" and not i["likely_case_specific"]
               for i in items)
