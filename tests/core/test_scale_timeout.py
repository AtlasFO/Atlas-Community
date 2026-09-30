"""Tests for size-aware timeout scaling (core.paths.scale_timeout)."""
import os

import pytest

from core.paths import scale_timeout, _input_size_bytes


class TestScaleTimeout:
    def test_missing_path_returns_base(self):
        assert scale_timeout(300, "/nonexistent/image.raw") == 300

    def test_none_and_empty_paths_return_base(self):
        assert scale_timeout(300, None, "") == 300

    def test_no_paths_returns_base(self):
        assert scale_timeout(300) == 300

    def test_small_file_returns_base(self, tmp_path):
        f = tmp_path / "small.raw"
        f.write_bytes(b"x" * 1024)
        assert scale_timeout(300, str(f)) == 300

    def test_directory_returns_base(self, tmp_path):
        assert scale_timeout(300, str(tmp_path)) == 300

    def test_large_file_scales(self, tmp_path, monkeypatch):
        f = tmp_path / "big.raw"
        f.write_bytes(b"x")
        real_stat = os.stat

        def fake_stat(path, *a, **kw):
            st = real_stat(path, *a, **kw)
            if str(path) == str(f):
                # Fake a 250 GB image without allocating it.
                fake_size = 250 * 1024**3

                class _St:
                    st_mode = st.st_mode
                    st_size = fake_size
                return _St()
            return st

        monkeypatch.setattr("core.paths.os.stat", fake_stat)
        # 250 GB at 20 MB/s floor → 12800 s, far above the 300 s base.
        assert scale_timeout(300, str(f)) == 250 * 1024**3 // (20 * 1024**2)

    def test_throughput_zero_disables_scaling(self, tmp_path):
        f = tmp_path / "big.raw"
        f.write_bytes(b"x" * 1024)
        assert scale_timeout(300, str(f), min_throughput_mb_s=0) == 300

    def test_custom_throughput(self, tmp_path):
        f = tmp_path / "img.raw"
        f.write_bytes(b"x" * (2 * 1024 * 1024))  # 2 MB
        # 2 MB at 1 MB/s = 2 s → still below base
        assert scale_timeout(300, str(f), min_throughput_mb_s=1) == 300
        # base 1 → scaled to 2
        assert scale_timeout(1, str(f), min_throughput_mb_s=1) == 2

    def test_multiple_paths_sum(self, tmp_path):
        a = tmp_path / "a.raw"
        b = tmp_path / "b.raw"
        a.write_bytes(b"x" * 1024 * 1024)
        b.write_bytes(b"x" * 1024 * 1024)
        assert scale_timeout(1, str(a), str(b), min_throughput_mb_s=1) == 2


class TestE01SegmentSumming:
    def test_e01_sums_sibling_segments(self, tmp_path):
        for name in ("img.E01", "img.E02", "img.E03"):
            (tmp_path / name).write_bytes(b"x" * 1024)
        assert _input_size_bytes(str(tmp_path / "img.E01")) == 3 * 1024

    def test_e01_without_siblings_uses_own_size(self, tmp_path):
        (tmp_path / "solo.E01").write_bytes(b"x" * 2048)
        assert _input_size_bytes(str(tmp_path / "solo.E01")) == 2048

    def test_non_e01_ignores_siblings(self, tmp_path):
        (tmp_path / "img.raw").write_bytes(b"x" * 1024)
        (tmp_path / "img.r02").write_bytes(b"x" * 1024)
        assert _input_size_bytes(str(tmp_path / "img.raw")) == 1024


class TestBackwardCompatibility:
    def test_tiny_or_missing_inputs_preserve_old_base(self, tmp_path):
        """Existing tool tests rely on the pre-scaling timeout values —
        small or absent inputs must return exactly the base."""
        small = tmp_path / "evidence.E01"
        small.write_bytes(b"header")
        for base in (300, 600, 3600, 21600):
            assert scale_timeout(base, str(small)) == base
            assert scale_timeout(base, "/no/such/file") == base
