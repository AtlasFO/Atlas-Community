"""Tests for tools/correlate.py — cross-tool correlation MCP tools."""
import json
import pytest
from unittest.mock import patch
from core.execution_log import ExecutionLog


def _seed_log(tmp_path):
    l = ExecutionLog()
    l.configure("CORR-001", str(tmp_path / "trace.json"))
    l.record_dair_call("Triage", "", False, "", "", "stay", "")
    return l


@pytest.fixture
def mitre_table(tmp_path, monkeypatch):
    """Seed a minimal MITRE techniques table so tests don't depend on the
    machine-local ~/cases/.common cache (absent on CI runners)."""
    table = {
        "techniques": {
            "T1003.003": {
                "name": "OS Credential Dumping: NTDS",
                "tactic": "credential-access",
                "description": "Extract the NTDS.dit Active Directory database.",
                "keywords": ["ntds.dit", "ntdsutil", "domain admin"],
            },
            "T1071.001": {
                "name": "Application Layer Protocol: Web Protocols",
                "tactic": "command-and-control",
                "description": "C2 over HTTP/HTTPS.",
                "keywords": ["web protocols", "http c2"],
            },
        }
    }
    path = tmp_path / "mitre_techniques.json"
    path.write_text(json.dumps(table))
    from tools.mitre import _load_json
    _load_json.cache_clear()
    monkeypatch.setattr("tools.correlate.DEFAULT_MITRE_PATH", str(path))
    monkeypatch.setattr("tools.mitre.DEFAULT_TECHNIQUES_PATH", str(path))
    return path


class TestProcessToFile:
    def test_correlation_by_path_match(self, tmp_path):
        from tools.correlate import process_to_file
        l = _seed_log(tmp_path)
        # vol output references a path
        l.record_tool_call(
            "vol -f mem.raw windows.psscan",
            True, False, 0, 0,
            stdout_excerpt="* 5024 cmd.exe PID=5024 C:\\Windows\\Temp\\toolx.exe",
        )
        # fls output mentions the same path
        l.record_tool_call(
            "fls -r /dev/loop0",
            True, False, 0, 0,
            stdout_excerpt="r/r * 1234: C:\\Windows\\Temp\\toolx.exe",
        )
        with patch("core.execution_log.log", l):
            r = process_to_file()
        assert r["success"] is True
        assert any(c["pid"] == 5024 for c in r["correlations"])
        assert any("toolx.exe" in c["candidate_path"] for c in r["correlations"])

    def test_pid_filter(self, tmp_path):
        from tools.correlate import process_to_file
        l = _seed_log(tmp_path)
        l.record_tool_call("vol psscan", True, False, 0, 0,
                           stdout_excerpt="5024 cmd.exe C:\\Windows\\foo.exe\n8000 svchost C:\\Windows\\bar.exe")
        l.record_tool_call("fls", True, False, 0, 0,
                           stdout_excerpt="r/r * 1: C:\\Windows\\foo.exe\nr/r * 2: C:\\Windows\\bar.exe")
        with patch("core.execution_log.log", l):
            r = process_to_file(pid=5024)
        pids_seen = {c["pid"] for c in r["correlations"]}
        assert pids_seen <= {5024}

    def test_no_match_returns_empty_correlations(self, tmp_path):
        from tools.correlate import process_to_file
        l = _seed_log(tmp_path)
        with patch("core.execution_log.log", l):
            r = process_to_file()
        assert r["success"] is True
        assert r["correlations"] == []


class TestNetworkToProcess:
    def test_correlation_basic(self, tmp_path):
        from tools.correlate import network_to_process
        l = _seed_log(tmp_path)
        l.record_tool_call(
            "vol windows.netscan", True, False, 0, 0,
            stdout_excerpt="TCP 10.0.0.10:443 -> 203.0.113.10:8443 ESTABLISHED 5024 cmd.exe",
        )
        l.record_tool_call(
            "vol windows.pslist", True, False, 0, 0,
            stdout_excerpt="* 5024 cmd.exe",
        )
        with patch("core.execution_log.log", l):
            r = network_to_process()
        assert r["success"] is True
        assert any(c["pid"] == 5024 for c in r["connections"])

    def test_ip_filter(self, tmp_path):
        from tools.correlate import network_to_process
        l = _seed_log(tmp_path)
        l.record_tool_call(
            "vol netscan", True, False, 0, 0,
            stdout_excerpt="TCP 10.0.0.1:80 5024 cmd.exe\nTCP 8.8.8.8:53 7000 svchost.exe",
        )
        l.record_tool_call("vol pslist", True, False, 0, 0,
                           stdout_excerpt="5024 cmd.exe\n7000 svchost.exe")
        with patch("core.execution_log.log", l):
            r = network_to_process(ip="10.0.0.1")
        assert all("10.0.0.1" in " ".join(c["ips"]) for c in r["connections"])


class TestMitreMap:
    def test_keyword_match_ranks_techniques(self, tmp_path, mitre_table):
        from tools.correlate import mitre_map
        l = _seed_log(tmp_path)
        with patch("core.execution_log.log", l):
            r = mitre_map("attacker extracted NTDS.dit via ntdsutil with Domain Admin rights")
        assert r["success"] is True
        tids = [c["technique_id"] for c in r["candidates"]]
        assert "T1003.003" in tids  # NTDS

    def test_no_match_returns_empty_candidates(self, tmp_path, mitre_table):
        from tools.correlate import mitre_map
        l = _seed_log(tmp_path)
        with patch("core.execution_log.log", l):
            r = mitre_map("xyzzy plover frob notarealthreat")
        assert r["success"] is True
        assert r["candidates"] == []

    def test_table_missing_returns_error(self, tmp_path):
        from tools.correlate import mitre_map
        nonexistent = str(tmp_path / "no_such_file.json")
        with patch("core.execution_log.log", _seed_log(tmp_path)):
            r = mitre_map("anything", table_path=nonexistent)
        assert r["success"] is False


class TestMitreValidate:
    def test_existing_technique(self, tmp_path, mitre_table):
        from tools.correlate import mitre_validate
        with patch("core.execution_log.log", _seed_log(tmp_path)):
            r = mitre_validate("T1003.003")
        assert r["success"] is True
        assert r["exists"] is True
        assert "NTDS" in r["name"]

    def test_nonexistent_technique(self, tmp_path):
        from tools.correlate import mitre_validate
        with patch("core.execution_log.log", _seed_log(tmp_path)):
            r = mitre_validate("T9999.999")
        assert r["exists"] is False

    def test_validate_with_custom_table(self, tmp_path):
        from tools.correlate import mitre_validate
        path = tmp_path / "custom_mitre.json"
        path.write_text(json.dumps({"techniques": {"T0001": {"name": "Test"}}}))
        with patch("core.execution_log.log", _seed_log(tmp_path)):
            r = mitre_validate("T0001", table_path=str(path))
        assert r["exists"] is True
        assert r["name"] == "Test"


class TestKillchainTimeline:
    def _seed(self, tmp_path):
        l = ExecutionLog()
        l.configure("KC-001", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        # Evidence → tool call the C2 finding will link back to.
        ev = l.record_tool_call("net.tcpdump_read c2.pcap", True, False, 0, 0,
                                stdout_excerpt="beacon to 203.0.113.10")
        # Findings recorded out of kill-chain order on purpose.
        l.record_finding("C2 beacon to 203.0.113.10", "CONFIRMED", linked_call_id=ev,
                         gate_metadata={"validated_techniques": [
                             {"technique_id": "T1071",
                              "name": "Application Layer Protocol",
                              "tactic": "Command and Control"}]})
        l.record_finding("Phishing email delivered the payload", "LIKELY",
                         gate_metadata={"validated_techniques": [
                             {"technique_id": "T1566", "name": "Phishing",
                              "tactic": "Initial Access"}]})
        return l, ev

    def test_orders_findings_along_killchain(self, tmp_path):
        from tools.correlate import killchain_timeline
        l, _ = self._seed(tmp_path)
        with patch("core.execution_log.log", l):
            r = killchain_timeline(infer_unlabeled=False)
        assert r["success"] is True
        order = [row["tactic"] for row in r["timeline"]]
        assert order == ["initial access", "command and control"]
        stage_tactics = [s["tactic"] for s in r["stages"]]
        assert stage_tactics.index("initial access") < \
            stage_tactics.index("command and control")

    def test_killchain_phase_rollup(self, tmp_path):
        from tools.correlate import killchain_timeline
        l, _ = self._seed(tmp_path)
        with patch("core.execution_log.log", l):
            r = killchain_timeline(infer_unlabeled=False)
        by_tid = {row["technique_id"]: row for row in r["timeline"]}
        assert by_tid["T1071"]["killchain_phase"] == "Command & Control"
        assert by_tid["T1566"]["killchain_phase"] == "Delivery"

    def test_evidence_to_tool_to_finding_lineage(self, tmp_path):
        from tools.correlate import killchain_timeline
        l, ev = self._seed(tmp_path)
        with patch("core.execution_log.log", l):
            r = killchain_timeline(infer_unlabeled=False)
        c2 = next(row for row in r["timeline"] if row["technique_id"] == "T1071")
        assert c2["source_tool"] == "net.tcpdump_read"
        assert c2["source_call_id"] == ev
        assert c2["linked_call_id"] == ev

    def test_unmapped_findings_collected(self, tmp_path):
        from tools.correlate import killchain_timeline
        l = ExecutionLog()
        l.configure("KC-002", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_finding("Some observation with no technique tag", "SUSPECTED")
        with patch("core.execution_log.log", l):
            r = killchain_timeline(infer_unlabeled=False)
        assert r["stats"]["findings_unmapped"] == 1
        assert r["stats"]["findings_mapped"] == 0
        assert r["timeline"] == []

    def test_infer_unlabeled_uses_mitre_map(self, tmp_path, monkeypatch):
        from tools import correlate
        l = ExecutionLog()
        l.configure("KC-003", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_finding("attacker used a scheduled task for persistence",
                         "LIKELY")
        monkeypatch.setattr(correlate, "mitre_map", lambda *a, **k: {
            "success": True, "candidates": [
                {"technique_id": "T1053", "name": "Scheduled Task",
                 "tactic": "Persistence"}]})
        with patch("core.execution_log.log", l):
            r = correlate.killchain_timeline(infer_unlabeled=True)
        assert r["stats"]["findings_mapped"] == 1
        row = r["timeline"][0]
        assert row["technique_id"] == "T1053"
        assert row["killchain_phase"] == "Installation"
        assert row["inferred"] is True

    def test_no_findings_is_clean_empty(self, tmp_path):
        from tools.correlate import killchain_timeline
        l = ExecutionLog()
        l.configure("KC-004", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        with patch("core.execution_log.log", l):
            r = killchain_timeline()
        assert r["success"] is True
        assert r["stages"] == [] and r["timeline"] == []
        assert r["stats"]["findings_total"] == 0
