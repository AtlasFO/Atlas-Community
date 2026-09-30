"""Tests for tools/_autodispatch.py — size-based background-job deferral."""
import pytest

from tools import _autodispatch
from tools._autodispatch import maybe_defer


def _big_file(tmp_path, mb):
    p = tmp_path / "image.raw"
    with open(p, "wb") as f:
        f.truncate(mb * 1_048_576)  # sparse — costs no real disk
    return str(p)


@pytest.fixture(autouse=True)
def _threshold_env(monkeypatch):
    monkeypatch.delenv("ATLAS_AUTODISPATCH", raising=False)
    monkeypatch.setenv("ATLAS_AUTODISPATCH_MB", "256")


def _fake_start(results):
    def start(kind, params):
        results.append((kind, params))
        return {"success": True, "job_id": "j-1", "kind": kind,
                "cmd": "cmd", "hint": "poll"}
    return start


class TestMaybeDefer:
    def test_small_evidence_runs_sync(self, tmp_path):
        small = _big_file(tmp_path, 10)
        assert maybe_defer("plaso_timeline", small, {}) is None

    def test_large_evidence_defers(self, tmp_path, monkeypatch):
        big = _big_file(tmp_path, 300)
        calls = []
        import tools.jobs as jobs
        monkeypatch.setattr(jobs, "_start_job", _fake_start(calls))
        r = maybe_defer("plaso_timeline", big, {"evidence_path": big})
        assert r is not None
        assert r["deferred"] is True and r["auto_dispatched"] is True
        assert r["job_id"] == "j-1"
        assert "job.job_status" in r["hint"]
        assert calls == [("plaso_timeline", {"evidence_path": big})]

    def test_env_kill_switch(self, tmp_path, monkeypatch):
        big = _big_file(tmp_path, 300)
        monkeypatch.setenv("ATLAS_AUTODISPATCH", "0")
        assert maybe_defer("plaso_timeline", big, {}) is None

    def test_job_start_failure_falls_back_to_sync(self, tmp_path, monkeypatch):
        big = _big_file(tmp_path, 300)
        import tools.jobs as jobs
        monkeypatch.setattr(jobs, "_start_job",
                            lambda kind, params: {"success": False,
                                                  "error": "no case"})
        assert maybe_defer("plaso_timeline", big, {}) is None

    def test_missing_evidence_runs_sync(self):
        assert maybe_defer("plaso_timeline", "/does/not/exist", {}) is None
        assert maybe_defer("plaso_timeline", None, {}) is None


class TestSyncToolIntegration:
    def test_plaso_create_timeline_defers_on_big_image(self, tmp_path, monkeypatch):
        big = _big_file(tmp_path, 300)
        calls = []
        import tools.jobs as jobs
        monkeypatch.setattr(jobs, "_start_job", _fake_start(calls))
        from tools.plaso import plaso_create_timeline
        fn = getattr(plaso_create_timeline, "fn", plaso_create_timeline)
        r = fn(big, str(tmp_path / "analysis" / "tl.plaso"))
        assert r["deferred"] is True
        assert calls[0][0] == "plaso_timeline"

    def test_bulk_extractor_defers_on_big_image(self, tmp_path, monkeypatch):
        big = _big_file(tmp_path, 300)
        calls = []
        import tools.jobs as jobs
        monkeypatch.setattr(jobs, "_start_job", _fake_start(calls))
        from tools.carving import bulk_extractor_scan
        fn = getattr(bulk_extractor_scan, "fn", bulk_extractor_scan)
        r = fn(big, str(tmp_path / "analysis" / "be_out"))
        assert r["deferred"] is True
        assert calls[0][0] == "bulk_extractor"
