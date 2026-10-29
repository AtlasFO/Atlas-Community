"""Read Windows event-log records in process with the python-evtx package.

The package's console scripts are not used: they import a ``scripts``
module the distribution does not install, so a tool built on them would be
advertised and then fail on the first call. The library itself works, and
reading in process also avoids a subprocess, PATH resolution and the
sandboxing rules that apply to external programs.

Kept free of tool-layer imports so it can be exercised wherever the Evtx
package is importable.
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Iterator, Optional


def available() -> bool:
    """Whether the Evtx package can be imported here."""
    try:
        import Evtx.Evtx  # noqa: F401
    except Exception:  # noqa: BLE001 — any import failure means "not available"
        return False
    return True


def iter_records(path: str | os.PathLike) -> Iterator[tuple[str, Optional[datetime]]]:
    """Yield ``(xml, timestamp)`` for each record in file order.

    A record that fails to render is skipped rather than ending the scan:
    one damaged chunk must not hide the rest of the log. The timestamp is
    the record header's, when readable; the XML still carries
    ``TimeCreated`` for callers that prefer it.
    """
    from Evtx.Evtx import Evtx

    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                xml = record.xml()
            except Exception:  # noqa: BLE001
                continue
            stamp: Optional[datetime] = None
            reader = getattr(record, "timestamp", None)
            if callable(reader):
                try:
                    stamp = reader()
                except Exception:  # noqa: BLE001
                    stamp = None
            yield xml, stamp


def parse_cursor(value: str | None) -> tuple[int, int]:
    """``"chunk:record"`` (both counted from 0 in file order) as a pair;
    ``(0, 0)`` for an empty or unreadable cursor."""
    try:
        chunk, _, rec = str(value or "").strip().partition(":")
        return max(0, int(chunk or 0)), max(0, int(rec or 0))
    except ValueError:
        return 0, 0


def chunk_counts(path: str | os.PathLike) -> Optional[list[int]]:
    """Each chunk's record count in file order from the chunk headers alone
    (last minus first record number plus one); None when they do not read."""
    from Evtx.Evtx import Evtx
    try:
        with Evtx(str(path)) as log:
            out = []
            for chunk in log.chunks():
                first, last = int(chunk.log_first_record_number()), int(chunk.log_last_record_number())
                out.append(last - first + 1 if last >= first else 0)
            return out
    except Exception:  # noqa: BLE001
        return None


def records_total(path: str | os.PathLike) -> Optional[int]:
    """The log's record count from its chunk headers alone."""
    counts = chunk_counts(path)
    return sum(counts) if counts is not None else None


def iter_from(path: str | os.PathLike, resume_from: str = "") -> Iterator[tuple[int, int, Optional[str],
                                                                                  Optional[datetime]]]:
    """Yield ``(chunk index, record index, xml, timestamp)`` in file order
    from the cursor on. Chunks before the cursor are passed by index without
    reading a record; inside the cursor's chunk the records before it are
    passed without rendering. A record that fails to render yields ``xml``
    None (the cursor still advances); a chunk whose records fail to read is
    passed. The position, not the record number, is the cursor, so a log
    whose numbering wraps is read once in file order."""
    from Evtx.Evtx import Evtx
    c0, r0 = parse_cursor(resume_from)
    with Evtx(str(path)) as log:
        for ci, chunk in enumerate(log.chunks()):
            if ci < c0:
                continue
            try:
                records = chunk.records()
                for ri, record in enumerate(records):
                    if ci == c0 and ri < r0:
                        continue
                    try:
                        xml = record.xml()
                    except Exception:  # noqa: BLE001
                        yield ci, ri, None, None
                        continue
                    stamp: Optional[datetime] = None
                    reader = getattr(record, "timestamp", None)
                    if callable(reader):
                        try:
                            stamp = reader()
                        except Exception:  # noqa: BLE001
                            stamp = None
                    yield ci, ri, xml, stamp
            except Exception:  # noqa: BLE001 - a damaged chunk is passed, the cursor moves on
                continue
