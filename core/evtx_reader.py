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
