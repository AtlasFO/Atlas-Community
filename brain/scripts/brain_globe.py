#!/usr/bin/env python3
"""Standalone wrapper — canonical logic in core/brain/globe.py."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.brain.globe import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
