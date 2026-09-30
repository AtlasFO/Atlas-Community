"""The report's evidence section states what the run established about each
image's integrity: the stored acquisition digest and its verification when
the image carries one, else the custody hash of the file as received."""
from __future__ import annotations

import json
from pathlib import Path

from core.report_assemble import _integrity_lines


def _plan(tmp_path: Path, images) -> Path:
    (tmp_path / ".atlas").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".atlas" / "mount_plan.json").write_text(json.dumps({"images": images}), encoding="utf-8")
    return tmp_path


def test_a_verified_acquisition_digest_is_stated(tmp_path):
    root = _plan(tmp_path, [{"basename": "notebook.E01", "hash_preflight": {
        "success": True, "full_hash": True, "md5": "a" * 32,
        "acquisition_hashes": {"md5": "b" * 32}, "acquisition_verified": True}}])
    lines = _integrity_lines(root)
    assert lines == [f"- `notebook.E01`: acquisition MD5 `{'b' * 32}` (verified by ewfverify)"]


def test_an_unverified_digest_and_a_mismatch_say_so(tmp_path):
    root = _plan(tmp_path, [
        {"basename": "big.E01", "hash_preflight": {"success": True, "acquisition_hashes": {"md5": "c" * 32},
                                                   "acquisition_verified": None}},
        {"basename": "bad.E01", "hash_preflight": {"success": True, "acquisition_hashes": {"md5": "d" * 32},
                                                   "acquisition_verified": False}}])
    lines = _integrity_lines(root)
    assert "stored digest, not re-verified" in lines[0] and "MISMATCH" in lines[1]


def test_a_raw_image_states_its_custody_hash(tmp_path):
    root = _plan(tmp_path, [
        {"basename": "disk.dd", "hash_preflight": {"success": True, "full_hash": True, "md5": "e" * 32}},
        {"basename": "huge.dd", "hash_preflight": {"success": True, "full_hash": False, "md5": "f" * 64}},
        {"basename": "failed.dd", "hash_preflight": {"success": False, "error": "unreadable"}}])
    lines = _integrity_lines(root)
    assert len(lines) == 2
    assert "custody hash of the file as received" in lines[0]
    assert "sampled fingerprint, full hash deferred" in lines[1]


def test_no_plan_no_lines(tmp_path):
    assert _integrity_lines(tmp_path) == []
