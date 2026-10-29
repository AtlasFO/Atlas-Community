"""The listing's guidance note names no file: guidance text in a tool's
output is Atlas's own words, and a file name in it would be read as
evidence wherever the output is mined (the recurring-indicator scan)."""
from __future__ import annotations


def test_the_listing_note_names_no_file(tmp_path, monkeypatch):
    from core.entities import discriminative, extract
    from tools.misc import list_evidence_dir
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "a.log").write_text("x", encoding="utf-8")
    monkeypatch.setattr("tools.misc._resolve_case_path", lambda p: str(tmp_path / p), raising=False)
    out = list_evidence_dir(str(tmp_path / "evidence"))
    note = out.get("note") or ""
    assert note and not [e for e in discriminative(extract(note)) if e.startswith(("file:", "path:"))]
