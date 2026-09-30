"""One value or a list under the same parameter is the candidate list a
search tool walks."""
from core.candidates import candidates


def test_a_string_is_one_candidate_and_a_list_is_taken_in_order():
    assert candidates("gator") == ["gator"]
    assert candidates(["gator", "monkey", "gator"]) == ["gator", "monkey"]
    assert candidates(None) == []


def test_the_empty_string_is_a_candidate_only_when_asked():
    assert candidates("") == []
    assert candidates("", keep_empty=True) == [""]
    assert candidates(["", "x", ""], keep_empty=True) == ["", "x"]
    assert candidates(["", "x"]) == ["x"]


def test_a_list_written_as_json_text_is_the_list():
    assert candidates('["a.jpg", "b.jpg"]') == ["a.jpg", "b.jpg"]
    assert candidates("[not json") == ["[not json"]
