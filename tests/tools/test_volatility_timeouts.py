"""A memory plugin's budget scales with the image it walks: the configured
base is the floor for a small image, and a large image gets the time a page
scanner needs to cross it, instead of a fixed budget that times out with no
output on the very images memory analysis exists for."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from core.paths import VOL_TIMEOUT
from tools import volatility as vol


@pytest.fixture
def small_image(tmp_path):
    p = tmp_path / "small.mem"
    p.write_bytes(b"\x00" * 4096)
    return str(p)


@pytest.fixture
def big_image(tmp_path):
    p = tmp_path / "big.mem"
    with open(p, "wb") as f:
        f.truncate(17 * 1024 ** 3)      # sparse: 17 GB of size, no blocks
    return str(p)


def test_a_small_image_keeps_the_configured_base(small_image):
    with patch("tools.volatility.run", return_value={"success": True}) as run:
        vol._vol(small_image, "windows.pslist")
    assert run.call_args.kwargs["timeout"] == VOL_TIMEOUT


def test_a_large_image_gets_the_time_a_scanner_needs(big_image):
    with patch("tools.volatility.run", return_value={"success": True}) as run:
        vol._vol(big_image, "windows.netscan")
    budget = run.call_args.kwargs["timeout"]
    assert budget > VOL_TIMEOUT
    assert budget >= (17 * 1024 ** 3) // (vol._SCAN_THROUGHPUT_MB_S * 1024 ** 2)


def test_the_progress_variant_scales_the_same_way(big_image):
    fake = AsyncMock(return_value={"success": True})
    with patch("tools.volatility.run_with_progress", fake):
        asyncio.run(vol._vol_progress(big_image, "windows.netscan", ctx=None))
    assert fake.call_args.kwargs["timeout"] > VOL_TIMEOUT
