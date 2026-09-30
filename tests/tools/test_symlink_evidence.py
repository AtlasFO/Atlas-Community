"""Tests for misc.symlink_evidence and batch_run's non-ASCII handling
(a non-ASCII evidence file name breaks raw-shell one-liners)."""
import os
from unittest.mock import patch

import pytest


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "evidence").mkdir()
    ev = tmp_path / "evidence" / "документ_report.pdf"
    ev.write_text("payload")
    return tmp_path, str(ev.relative_to(tmp_path))


class TestSymlinkEvidence:
    def test_creates_ascii_safe_link(self, case):
        root, ev = case
        from tools.misc import symlink_evidence
        r = symlink_evidence(ev)
        assert r["success"] is True
        assert r["safe_name"].isascii()
        assert os.path.exists(r["link_path"])
        assert os.path.realpath(r["link_path"]) == os.path.realpath(root / ev)

    def test_idempotent(self, case):
        _, ev = case
        from tools.misc import symlink_evidence
        first = symlink_evidence(ev)
        second = symlink_evidence(ev)
        assert second["link_path"] == first["link_path"]
        assert "already exists" in second["note"]

    def test_missing_file(self, case):
        from tools.misc import symlink_evidence
        assert symlink_evidence("evidence/nope.bin")["success"] is False

    def test_evidence_destination_rejected(self, case):
        _, ev = case
        from tools.misc import symlink_evidence
        with pytest.raises(Exception):
            symlink_evidence(ev, link_dir="evidence")


class TestBatchRunNonAscii:
    def test_warns_on_nonascii_arg(self, case):
        _, ev = case
        from tools.misc import batch_run
        with patch("tools.misc.run", return_value={"success": True, "stdout": ""}):
            r = batch_run([{"cmd": ["cat", ev], "force": True}])
        res = r["results"][0]
        assert "warning" in res and "symlink_evidence" in res["warning"]

    def test_syntaxerror_hint(self, case):
        from tools.misc import batch_run
        fail = {"success": False, "stderr": "  SyntaxError: invalid syntax"}
        with patch("tools.misc.run", return_value=fail):
            r = batch_run([{"cmd": ["python3", "-c", "print('x'"], "force": True}])
        assert "hint" in r["results"][0]
        assert "heredoc" in r["results"][0]["hint"]
