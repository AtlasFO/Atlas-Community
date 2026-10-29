"""The package reader opens only regular files of the package
(core.coverage_ledger._opc_part, _package_structure): a FIFO or a link named
like a package part gives nothing and never blocks, also when the file is
swapped between the check and the open, and a file reached through a link
out of the unit is never read. Invented parts only."""
from __future__ import annotations

import os
import threading

import pytest

from core import coverage_ledger as cl
from tests.core.test_package_structure import RELS_NS, TYPES_NS, _rels, _types

STREAM = "[Content_Types].xml"


def _read(path, timeout=5.0):
    """_opc_part on ``path`` in a thread: a read that blocks fails the test
    (the FIFO is released first, so no thread stays behind)."""
    box: dict = {}
    t = threading.Thread(target=lambda: box.setdefault(
        "out", cl._opc_part(str(path), "Types", TYPES_NS, cl._opc_types)), daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        try:
            os.close(os.open(str(path), os.O_WRONLY | os.O_NONBLOCK))
        except OSError:
            pass
        t.join(timeout)
        pytest.fail("the read of a package part blocked")
    return box["out"]


def _opens(monkeypatch):
    opened: list[str] = []
    real = os.open
    monkeypatch.setattr(cl.os, "open", lambda p, *a, **k: opened.append(str(p)) or real(p, *a, **k))
    return opened


def _seen_as_regular(monkeypatch, path, like):
    """The check sees a regular file at ``path`` (swapped after the check)."""
    real = os.lstat
    monkeypatch.setattr(cl.os, "lstat", lambda p, *a, **k: real(like) if str(p) == str(path) else real(p, *a, **k))


@pytest.fixture
def stream(tmp_path):
    f = tmp_path / "outside" / STREAM
    f.parent.mkdir()
    f.write_text(_types(), encoding="utf-8")
    assert cl._opc_part(str(f), "Types", TYPES_NS, cl._opc_types) is not None     # the real stream parses
    return f


def test_a_fifo_named_like_the_stream_is_never_opened(tmp_path, monkeypatch):
    fifo = tmp_path / STREAM
    os.mkfifo(fifo)
    opened = _opens(monkeypatch)
    assert _read(fifo) is None and str(fifo) not in opened


def test_a_symlink_named_like_the_stream_is_never_opened(tmp_path, monkeypatch, stream):
    (tmp_path / "pkg").mkdir()
    link = tmp_path / "pkg" / STREAM
    link.symlink_to(stream)
    opened = _opens(monkeypatch)
    assert _read(link) is None and str(link) not in opened


def test_a_link_swapped_in_after_the_check_is_not_followed(tmp_path, monkeypatch, stream):
    (tmp_path / "pkg").mkdir()
    link = tmp_path / "pkg" / STREAM
    link.symlink_to(stream)
    _seen_as_regular(monkeypatch, link, stream)
    assert _read(link) is None


def test_a_fifo_swapped_in_after_the_check_neither_blocks_nor_is_read(tmp_path, monkeypatch, stream):
    fifo = tmp_path / STREAM
    os.mkfifo(fifo)
    _seen_as_regular(monkeypatch, fifo, stream)
    assert _read(fifo) is None                                       # no writer: the open does not wait
    cl._OPC_MEMO.clear()
    # A writer that has written a whole stream and closes once the reader has
    # opened: what the reader would read is the stream, then the end.
    writer = os.open(str(fifo), os.O_RDWR | os.O_NONBLOCK)
    os.write(writer, _types().encode())
    real = os.open

    def open_then_close_writer(p, *a, **k):
        fd = real(p, *a, **k)
        if str(p) == str(fifo):
            os.close(writer)
        return fd
    monkeypatch.setattr(cl.os, "open", open_then_close_writer)
    assert _read(fifo) is None                                       # opened, but no regular file: not read


def test_a_file_reached_through_a_link_out_of_the_unit_is_never_read(tmp_path, monkeypatch):
    unit = tmp_path / "unit"
    outside = tmp_path / "elsewhere"
    for d in (unit / "_rels", outside / "_rels"):
        d.mkdir(parents=True)
    for root in (unit, outside):
        (root / STREAM).write_text(_types(), encoding="utf-8")
        (root / "_rels" / ".rels").write_text(_rels(("officeDocument", "word/document.xml", False)), encoding="utf-8")
    inside = [str(unit / STREAM), str(unit / "_rels" / ".rels")]
    assert cl._package_structure(str(unit), inside) == set(inside)  # the unit's own package
    read: list[str] = []
    real = cl._opc_part
    monkeypatch.setattr(cl, "_opc_part", lambda p, *a: read.append(p) or real(p, *a))
    # the extracted outputs give each file resolved: a link to elsewhere arrives as its target
    assert cl._package_structure(str(unit), [str(outside / STREAM), str(outside / "_rels" / ".rels")]) == set()
    assert not any(p.startswith(str(outside)) for p in read)
