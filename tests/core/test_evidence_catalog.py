"""The evidence catalog reads a file again only when it may have changed."""
from __future__ import annotations

import os
from pathlib import Path

from core import evidence_catalog as ec


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "evidence" / "CORP-DC01.raw").write_bytes(b"\x00" * 4096)
    (case / "evidence" / "notes.txt").write_text("jane.doe 2031-03-04\n", encoding="utf-8")
    old = 1_000_000_000  # long before any hash in this test (a hash after a
    # file time in the future is never trusted)
    for p in (case / "evidence").iterdir():
        os.utime(p, (old, old))
    return case


def _count_reads(monkeypatch) -> list[str]:
    reads: list[str] = []
    real = ec.fingerprint_file

    def counting(path, **kw):
        reads.append(Path(path).name)
        return real(path, **kw)
    monkeypatch.setattr(ec, "fingerprint_file", counting)
    return reads


def test_an_unchanged_file_keeps_its_hash_without_a_read(tmp_path, monkeypatch):
    case = _case(tmp_path)
    first = ec.scan_evidence(case)
    reads = _count_reads(monkeypatch)
    second = ec.scan_evidence(case, previous={"units": first})
    assert reads == []
    assert {u["content_sha256"] for u in second.values()} == {u["content_sha256"] for u in first.values()}
    assert all(u["fingerprint_mode"] == "full" for u in second.values())


def test_a_changed_or_forced_file_is_read_again(tmp_path, monkeypatch):
    case = _case(tmp_path)
    first = ec.scan_evidence(case)
    target = case / "evidence" / "notes.txt"
    target.write_text("jane.doe 2031-03-05\n", encoding="utf-8")
    os.utime(target, (1_000_000_100, 1_000_000_100))
    reads = _count_reads(monkeypatch)
    ec.scan_evidence(case, previous={"units": first})
    assert reads == ["notes.txt"]
    reads.clear()
    ec.scan_evidence(case, previous={"units": first}, force_full_hash=True)
    assert sorted(reads) == ["CORP-DC01.raw", "notes.txt"]


def test_a_hash_taken_just_after_the_last_write_is_taken_again(tmp_path, monkeypatch):
    case = _case(tmp_path)
    first = ec.scan_evidence(case)
    for unit in first.values():
        unit["hashed_at_ns"] = unit["mtime_ns"] + 1_000_000_000   # within the racy window
    reads = _count_reads(monkeypatch)
    ec.scan_evidence(case, previous={"units": first})
    assert sorted(reads) == ["CORP-DC01.raw", "notes.txt"]


def test_a_unit_recorded_before_the_stamp_is_reused_on_its_stat(tmp_path, monkeypatch):
    case = _case(tmp_path)
    first = ec.scan_evidence(case)
    for unit in first.values():
        unit.pop("hashed_at_ns")
    reads = _count_reads(monkeypatch)
    ec.scan_evidence(case, previous={"units": first})
    assert reads == []


def test_the_scan_says_where_it_stands_without_flooding(tmp_path, monkeypatch):
    """The first fingerprinting of a large case takes minutes: the scan names
    its position before the first file, at most every few seconds, and
    after the last, with the byte totals."""
    import core.evidence_catalog as ec
    ev = tmp_path / "evidence"
    ev.mkdir()
    for n, size in enumerate((1000, 2000, 3000)):
        (ev / f"CORP-WS0{n}.bin").write_bytes(b"x" * size)
    ticks = [0.0, 0.5, 9.0, 9.5]
    monkeypatch.setattr(ec.time, "monotonic",
                        lambda: ticks.pop(0) if len(ticks) > 1 else ticks[0])
    heard = []
    ec.scan_evidence(tmp_path, progress=lambda *a: heard.append(a))
    # Before the first file, the second file after the pause, the last file;
    # the first file came too soon after the start to be reported.
    assert [h[0] for h in heard] == [0, 2, 3]
    assert heard[0] == (0, 3, 0, 6000) and heard[-1] == (3, 3, 6000, 6000)


def test_a_failing_listener_never_stops_the_scan(tmp_path):
    from core.evidence_catalog import scan_evidence
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "CORP-WS01.bin").write_bytes(b"x")

    def boom(*_a):
        raise RuntimeError("listener broke")
    assert len(scan_evidence(tmp_path, progress=boom)) == 1
