"""A synthesis heading that contains the word "blocker" speaks about the
lines under it; when those say there is none, the heading is not a
blocker. A heading followed by an item still is."""
from tools.reasoning import _blocker_sentences, _has_unnegated_blocker

CLEAN = (
    "=== MISSING INVESTIGATION ===\n\nEVIDENCE EXHAUSTION (potential BLOCKERS):\n\n"
    "None identified. The case does not conclude \"identity unknown\" anywhere.\n\n"
    "COLLECTION GAPS (ADVISORY - not blockers):\n\n1. No memory image: expected for the era.\n\n"
    "=== BLOCKER ASSESSMENT ===\n\nNo BLOCKER conditions are met. The core identification is supported.\n")

REAL = (
    "=== BLOCKER ASSESSMENT ===\n\n1. The memory image was never parsed; the C2 question rests on it.\n")


def test_headings_whose_body_says_none_are_not_blockers():
    assert _has_unnegated_blocker(CLEAN) is False
    assert _blocker_sentences(CLEAN) == ""


def test_a_heading_followed_by_an_item_is_still_a_blocker():
    assert _has_unnegated_blocker(REAL) is True


def test_a_plain_prose_blocker_is_unchanged():
    assert _has_unnegated_blocker("The unparsed hive is a blocker for the persistence question.")
    assert not _has_unnegated_blocker("There are no blockers left; all gaps are advisory.")
