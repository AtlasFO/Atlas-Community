#!/usr/bin/env python3
"""Standalone wrapper for any LLM agent — canonical logic in core/brain/indexes.py."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.brain.indexes import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
