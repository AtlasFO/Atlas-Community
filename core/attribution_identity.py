"""What the attribution gates' identity-row test
(ATLAS_ATTRIBUTION_IDENTITY_ROWS; tools/_gates/_identity_rows.py) reads from
core: its switch, and the one source of a person's account spellings
(``person_variants``), read by the gate and by the reference-set tools."""
from __future__ import annotations

import os
import re
from typing import Iterable


def likely_attribution_evaluation_on() -> bool:
    """A LIKELY attribution verdict that passes its gates is
    evaluated adversarially (the finding auto-evaluation with the external
    look-up first)."""
    from core.envfile import env_flag
    evaluate = (os.environ.get("ATLAS_FINDING_AUTO_EVALUATE") or "1").strip().lower() not in (
        "0", "false", "no", "off")
    return evaluate and env_flag("ATLAS_EXTERNAL_LOOKUP_FIRST")


def identity_rows_on() -> bool:
    """The identity-row test is the mechanical layer under the evaluation of
    LIKELY attribution verdicts; it acts only while that evaluation is on."""
    from core.envfile import env_flag
    return env_flag("ATLAS_ATTRIBUTION_IDENTITY_ROWS", True) and likely_attribution_evaluation_on()


def person_variants(full_name: str) -> list[str]:
    """The username and mail-prefix spellings of 'Firstname Lastname':
    initial plus last, first.last, first_last, last plus initial, first plus
    last, and the bare first and last names. Lowercased."""
    parts = [p for p in full_name.strip().lower().split() if p]
    if not parts:
        return []
    if len(parts) == 1:
        return [parts[0]]
    first, *_, last = parts
    return [
        first + last,
        first + "." + last,
        first + "_" + last,
        first[0] + last,
        first[0] + last + first[0],
        first[0] + "." + last,
        last + first[0],
        first,
        last,
    ]


def full_names(first: str, texts: Iterable[str]) -> list[str]:
    """Every 'First Last' in the texts that begins with the given name."""
    out: list[str] = []
    rx = re.compile(rf"\b{re.escape(first)}\s+([A-Z][a-z]{{1,30}})\b")
    for t in texts:
        for m in rx.finditer(t or ""):
            name = f"{first} {m.group(1)}"
            if name not in out:
                out.append(name)
    return out
