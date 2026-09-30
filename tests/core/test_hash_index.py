"""A file hashed anywhere in the case is matched to every other path with
the same content, evidence included, and the knowledge index lists them."""
import hashlib

from core import hash_index
from core.call_memo import CallMemo, render_index
from core.evidence_catalog import empty_catalog, save_catalog

SAME = b"same bytes"
SHA = hashlib.sha256(SAME).hexdigest()


def _case(tmp_path):
    case = tmp_path / "CASE"
    (case / "evidence").mkdir(parents=True)
    (case / "analysis" / "carved").mkdir(parents=True)
    (case / "exports").mkdir()
    (case / "evidence" / "photo.jpg").write_bytes(SAME)
    (case / "evidence" / "other.jpg").write_bytes(b"other bytes")
    cat = empty_catalog("CASE")
    cat["units"]["ev1"] = {"evidence_id": "ev1", "path": "evidence/photo.jpg",
                          "content_sha256": SHA, "fingerprint_mode": "full"}
    cat["units"]["ev2"] = {"evidence_id": "ev2", "path": "evidence/other.jpg",
                          "content_sha256": hashlib.sha256(b"other bytes").hexdigest(),
                          "fingerprint_mode": "sampled"}
    save_catalog(case, cat)
    return case


def test_a_carved_copy_is_matched_to_the_evidence_file(tmp_path):
    case = _case(tmp_path)
    carved = case / "analysis" / "carved" / "0001.jpg"
    carved.write_bytes(SAME)
    matches = hash_index.record(str(case), [(str(carved), SHA)])
    assert matches == {"analysis/carved/0001.jpg":
                       [{"path": "evidence/photo.jpg", "source": "evidence"}]}
    export = case / "exports" / "copy.jpg"
    export.write_bytes(SAME)
    others = hash_index.record(str(case), [(str(export), SHA)])["exports/copy.jpg"]
    assert [o["path"] for o in others] == ["evidence/photo.jpg", "analysis/carved/0001.jpg"]
    assert hash_index.identical_groups(str(case)) == [
        {"sha256": SHA,
         "paths": ["evidence/photo.jpg", "analysis/carved/0001.jpg", "exports/copy.jpg"]}]


def test_a_sampled_fingerprint_is_not_a_content_hash(tmp_path):
    case = _case(tmp_path)
    sha = hashlib.sha256(b"other bytes").hexdigest()
    assert hash_index.record(str(case), [(str(case / "exports" / "x.bin"), sha)]) == {}
    assert hash_index.identical_groups(str(case)) == []


def test_hash_file_reports_the_identical_evidence_file(tmp_path, monkeypatch):
    from tools import hashing
    case = _case(tmp_path)
    monkeypatch.setattr(hashing, "_HASH_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setattr(hashing, "_HASH_CACHE", None)
    monkeypatch.setattr("core.execution_log.log.case_dir", lambda: str(case))
    carved = case / "analysis" / "carved" / "0001.jpg"
    carved.write_bytes(SAME)
    result = hashing.hash_file(str(carved))
    assert result["sha256"] == SHA
    assert result["identical_to"] == [{"path": "evidence/photo.jpg", "source": "evidence"}]
    assert "one file under several paths" in result["note"]
    again = hashing.hash_file(str(carved))
    assert again["cache_hit"] is True and again["identical_to"] == result["identical_to"]
    listing = hashing.hash_directory(str(case / "analysis"))
    assert listing["identical_files"] == 1
    assert listing["hashes"][0]["identical_to"] == ["evidence/photo.jpg"]


def test_knowledge_index_lists_copies():
    text = render_index(CallMemo(), identical=[
        {"sha256": "ab" * 32, "paths": ["evidence/a.jpg", "exports/b.jpg"]}])
    assert "evidence/a.jpg, exports/b.jpg" in text
    assert "identical" not in render_index(CallMemo()).lower()
