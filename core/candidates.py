"""One candidate or several, under one parameter.

A tool whose natural use is "try these" (a passphrase against a carrier, a
password against an archive, a key against a ciphertext) takes a single
value or a list under the same parameter, and walks the candidates itself.
Otherwise the loop runs in the model, one round trip per candidate, and a
search over a few dozen cells costs more than the case's whole budget for
the question while never reaching the negative it could have stated.
"""
from __future__ import annotations

import json
from typing import Iterable


def candidates(value: str | Iterable[str] | None, *,
               keep_empty: bool = False) -> list[str]:
    """``value`` as an ordered list of distinct candidates.

    A string is one candidate; a list is taken in order. ``None`` is none.
    The empty string is a candidate only when ``keep_empty`` (an empty
    passphrase is a real attempt; an empty password is not).
    """
    if value is None:
        return []
    if isinstance(value, str) and value.lstrip().startswith("["):
        # A list written as its JSON text is the list: some models send
        # arrays that way whatever the schema says.
        try:
            parsed = json.loads(value)
        except ValueError:
            parsed = None
        if isinstance(parsed, list):
            value = parsed
    items = [value] if isinstance(value, (str, bytes)) else list(value)
    out: list[str] = []
    for item in items:
        if item is None:
            continue
        text = item.decode() if isinstance(item, bytes) else str(item)
        if text == "" and not keep_empty:
            continue
        if text not in out:
            out.append(text)
    return out
