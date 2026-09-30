"""Tests for misc.batch_run's up-front MCP-wrapper redirect.

Raw-shell forensic binaries that have a dedicated MCP wrapper are rejected so
the agent uses the citable typed surface instead.
"""
from unittest.mock import patch


class TestBatchRunRouting:
    def test_wrapped_binary_rejected(self):
        from tools.misc import batch_run
        r = batch_run([{"cmd": ["tcpdump", "-r", "x.pcap"]}])
        res = r["results"][0]
        assert res["success"] is False
        assert "redirect_to" in res
        assert "net." in res["redirect_to"]

    def test_force_overrides_redirect(self):
        from tools.misc import batch_run
        with patch("tools.misc.run", return_value={"success": True}) as m:
            r = batch_run([{"cmd": ["tcpdump", "--version"], "force": True}])
        assert m.called
        assert "redirect_to" not in r["results"][0]

    def test_unwrapped_binary_runs(self):
        from tools.misc import batch_run
        with patch("tools.misc.run", return_value={"success": True}) as m:
            r = batch_run([{"cmd": ["7z", "x", "-p2024", "a.zip"]}])
        assert m.called
        assert "redirect_to" not in r["results"][0]

    def test_invalid_cmd_still_reported(self):
        from tools.misc import batch_run
        r = batch_run([{"cmd": None}])
        assert r["results"][0]["success"] is False
