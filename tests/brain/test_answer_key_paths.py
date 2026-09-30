"""answer_key.answer_key_paths — enumerate every grading file the framework
recognises for a case (feeds the positive-identifier gate and the stash)."""
from pathlib import Path

from core.brain import answer_key


def test_root_ground_truth(tmp_path):
    (tmp_path / "ground_truth.json").write_text("{}")
    assert answer_key.answer_key_paths(tmp_path) == [
        tmp_path / "ground_truth.json"]


def test_all_known_locations(tmp_path):
    (tmp_path / "ground_truth.json").write_text("{}")
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "ground_truth.json").write_text("{}")
    (tmp_path / "analysis").mkdir()
    (tmp_path / "analysis" / "ground_truth.json").write_text("{}")
    found = {str(p) for p in answer_key.answer_key_paths(tmp_path)}
    assert found == {
        str(tmp_path / "ground_truth.json"),
        str(tmp_path / "evidence" / "ground_truth.json"),
        str(tmp_path / "analysis" / "ground_truth.json"),
    }


def test_none_when_absent(tmp_path):
    assert answer_key.answer_key_paths(tmp_path) == []


def test_accepts_str_and_never_raises():
    # A bad/nonexistent case_dir yields no keys rather than raising.
    assert answer_key.answer_key_paths("/does/not/exist") == []
    assert answer_key.answer_key_paths(None) == []  # type: ignore[arg-type]


def test_matches_find_ground_truth_first(tmp_path):
    """answer_key_paths is a superset of _find_ground_truth's single hit."""
    (tmp_path / "ground_truth.json").write_text("{}")
    first = answer_key._find_ground_truth(Path(tmp_path))
    assert first in answer_key.answer_key_paths(tmp_path)
