#!/usr/bin/env python3
"""Standalone wrapper — canonical logic in core/brain/capture.py.

Usage: python brain/scripts/capture_run_memory.py --case DIR
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.brain.capture import CaptureError, capture_case  # noqa: E402

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Stage memory candidates from a finished case run")
    parser.add_argument("--case", required=True, help="case directory")
    args = parser.parse_args()
    try:
        summary = capture_case(Path(args.case).expanduser().resolve())
    except CaptureError as e:
        raise SystemExit(f"error: {e}")
    print(f"Staged {summary['candidates']} memory candidate(s); "
          f"run summary: {summary['run_summary']}")
