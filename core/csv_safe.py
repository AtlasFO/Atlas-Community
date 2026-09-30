"""One guard for every CSV cell Atlas writes.

A spreadsheet executes a cell that starts with a formula character, so a
value that begins with one gets a leading quote and stays text. Tab and
carriage return open the same door in some importers and are guarded the
same way.
"""
from __future__ import annotations

_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value) -> str:
    v = "" if value is None else str(value)
    return "'" + v if v[:1] in _FORMULA_LEADERS else v
