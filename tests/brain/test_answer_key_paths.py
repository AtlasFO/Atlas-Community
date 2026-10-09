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


def _files(base: Path, *rels: str) -> None:
    for rel in rels:
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{}")


def test_copies_and_variants_anywhere_in_the_case_outputs_are_found(tmp_path):
    """One name test for every layer: a copy under .atlas/ or analysis/,
    a ground truth in another language, an answers file beside the brief."""
    _files(tmp_path, "ground_truth.json", "ground_truth.en.json", ".atlas/ground_truth.json",
           "analysis/scratch/answers.json", "evidence/ground_truth.de.json",
           "notes/ground_truths_overview.md", "evidence/CORP-WS01/ground_truth.json",
           "mnt/CORP-WS01/ground_truth.json", "exports/ground_truth.json")
    found = [p.relative_to(tmp_path).as_posix() for p in answer_key.answer_key_paths(tmp_path)]
    assert found[0] == "ground_truth.json"                # the grading key leads
    assert sorted(found) == sorted([
        "ground_truth.json", "ground_truth.en.json", ".atlas/ground_truth.json",
        "analysis/scratch/answers.json", "evidence/ground_truth.de.json"])


def test_a_linked_copy_is_left_to_the_realpath_gate(tmp_path):
    outside = tmp_path / "elsewhere" / "ground_truth.json"
    _files(tmp_path / "elsewhere", "ground_truth.json")
    case = tmp_path / "CASE-A"
    (case / ".atlas").mkdir(parents=True)
    (case / ".atlas" / "ground_truth.json").symlink_to(outside)
    assert answer_key.answer_key_paths(case) == []


def test_every_copy_is_stashed_and_put_back(tmp_path, monkeypatch):
    from core import paths
    monkeypatch.setenv("ATLAS_ANSWER_KEY_STASH_DIR", str(tmp_path / "stash"))
    case = tmp_path / "CASE-A"
    _files(case, "ground_truth.json", "ground_truth.en.json", ".atlas/ground_truth.json")
    records = paths.stash_answer_keys(case)
    assert len(records) == 3
    assert not any((case / r).exists() for r in (
        "ground_truth.json", "ground_truth.en.json", ".atlas/ground_truth.json"))
    paths.restore_answer_keys(records)
    assert all((case / r).is_file() for r in (
        "ground_truth.json", "ground_truth.en.json", ".atlas/ground_truth.json"))


def test_a_large_folder_does_not_hide_a_shallow_copy_after_it(tmp_path, monkeypatch):
    """The search goes level by level: a folder of parser output with
    thousands of files that sorts first delays no copy one level down in a
    folder that sorts after it. A copy deeper than the search reaches is
    left to the name gate."""
    monkeypatch.setattr(answer_key, "_KEY_SEARCH_ENTRIES", 5000)
    bulk = tmp_path / "analysis" / "aaa_eztools"
    bulk.mkdir(parents=True)
    for n in range(2100):
        (bulk / f"CORP-WS01_{n:05d}.csv").touch()
    _files(tmp_path, "analysis/zzz_grader/ground_truth.json",
           "analysis/a/b/c/d/e/ground_truth.json")
    found = {p.relative_to(tmp_path).as_posix() for p in answer_key.answer_key_paths(tmp_path)}
    assert found == {"analysis/zzz_grader/ground_truth.json"}


def test_a_folder_too_large_for_the_budget_is_skipped_not_the_end(tmp_path, monkeypatch):
    """A folder the remaining budget cannot list is skipped; the folders
    after it on the same level are still searched."""
    monkeypatch.setattr(answer_key, "_KEY_SEARCH_ENTRIES", 5000)
    bulk = tmp_path / "analysis" / "aaa_carve"
    bulk.mkdir(parents=True)
    for n in range(5100):
        (bulk / f"CORP-WS01_{n:05d}.bin").touch()
    _files(tmp_path, "analysis/zzz_grader/ground_truth.json")
    found = {p.relative_to(tmp_path).as_posix() for p in answer_key.answer_key_paths(tmp_path)}
    assert found == {"analysis/zzz_grader/ground_truth.json"}
