"""CASE-derived investigation intents — opt-in hypotheses, not silent curriculum.

Generic gates must not assume a particular investigation hypothesis (e.g. BadUSB)
for every case that happens to contain removable media. Intents are derived from:

1. Explicit CASE.md / case.md prose (investigator-stated questions)
2. Optional ``.atlas/case_config.json`` ``intents`` flags
3. Finding text that itself raises the hypothesis (claim-driven, not silent)

See architecture review: hardcoding-critical-review-v2 (silent investigation knowledge).
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Optional

# Investigator or finding explicitly raises HID / keystroke-injection hypothesis.
# Product nicknames (Rubber Ducky) are intent vocabulary here, not case IOCs.
_HID_INJECTION_RE = re.compile(
    r"(?i)\b(?:"
    r"bad\s*usb|badusb|hid\s*inject|keystroke\s*inject|"
    r"rubber\s*ducky|malicious\s*(?:usb|hid|device)|"
    r"rogue\s*(?:usb|hid|device)|hardware\s*keylogger|"
    r"keystroke[- ]injection|hid[- ]capable\s*inject"
    r")\b"
)


def _case_root(case_dir: str | os.PathLike | None) -> Optional[Path]:
    if not case_dir:
        return None
    try:
        return Path(case_dir).resolve()
    except Exception:
        return None


def _read_case_md(root: Path) -> str:
    bits: list[str] = []
    for name in ("CASE.md", "case.md"):
        p = root / name
        if p.is_file():
            try:
                bits.append(p.read_text(encoding="utf-8", errors="replace")[:20000])
            except Exception:
                pass
    return "\n".join(bits)


def _config_intents(root: Path) -> dict[str, Any]:
    try:
        from core.case_config import load_case_config
        cfg = load_case_config(root) or {}
        intents = cfg.get("intents")
        return intents if isinstance(intents, dict) else {}
    except Exception:
        return {}


def considers_hid_injection(
    case_dir: str | os.PathLike | None = None,
    *,
    finding_text: str = "",
) -> bool:
    """True when HID/keystroke-injection is an explicit investigation intent.

    Silent default is False — removable media alone must not enable BadUSB law.
    """
    blob = finding_text or ""
    if _HID_INJECTION_RE.search(blob):
        return True
    root = _case_root(case_dir)
    if root is None:
        return False
    intents = _config_intents(root)
    if intents.get("hid_injection") or intents.get("badusb"):
        return True
    return bool(_HID_INJECTION_RE.search(_read_case_md(root)))
