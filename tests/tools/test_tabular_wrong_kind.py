"""table.* must refuse binary / directory inputs with wrong_input_kind."""
from __future__ import annotations

from pathlib import Path

from tools.tabular import table_grep, table_query, table_schema


def _fn(tool):
    return getattr(tool, "fn", tool)


def test_binary_hive_refused(tmp_path: Path):
    hive = tmp_path / "Amcache.hve"
    hive.write_bytes(b"regf" + b"\x00" * 64)
    r = _fn(table_query)(str(hive), where=["Name=x"])
    assert r["success"] is False
    assert r.get("gate") == "wrong_input_kind"
    assert "tabular" in r["error"].lower() or "binary" in r["error"].lower()


def test_nul_mislabeled_csv_refused(tmp_path: Path):
    p = tmp_path / "export.csv"
    p.write_bytes(b"col1,col2\n" + b"\x00\x01\x02binary")
    r = _fn(table_schema)(str(p))
    assert r["success"] is False
    assert r.get("gate") == "wrong_input_kind"
    assert "NUL" in r["error"]


def test_directory_refused(tmp_path: Path):
    d = tmp_path / "exports"
    d.mkdir()
    r = _fn(table_grep)(str(d), pattern="admin")
    assert r["success"] is False
    assert r.get("gate") == "wrong_input_kind"
    assert "directory" in r["error"].lower()


def test_real_csv_still_works(tmp_path: Path):
    p = tmp_path / "events.csv"
    p.write_text("user,host\nadmin,PC01\n", encoding="utf-8")
    r = _fn(table_schema)(str(p))
    assert r["success"] is True
