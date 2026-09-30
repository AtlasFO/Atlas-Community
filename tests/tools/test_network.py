"""Tests for tools/network.py."""
import pytest
from unittest.mock import patch, MagicMock

PCAP = "/captures/traffic.pcap"


@pytest.fixture(autouse=True)
def mock_run(run_ok):
    with patch("tools.network.run", return_value=run_ok) as m:
        yield m


class TestTcpdumpRead:
    def test_basic_read(self, mock_run):
        from tools.network import tcpdump_read
        tcpdump_read(PCAP)
        cmd = mock_run.call_args[0][0]
        assert "tcpdump" in cmd
        assert "-r" in cmd
        assert PCAP in cmd

    def test_with_filter(self, mock_run):
        from tools.network import tcpdump_read
        tcpdump_read(PCAP, filter_expr="tcp and port 443")
        cmd = mock_run.call_args[0][0]
        assert "tcp" in cmd
        assert "443" in cmd

    def test_count_applied(self, mock_run):
        from tools.network import tcpdump_read
        tcpdump_read(PCAP, count=50)
        cmd = mock_run.call_args[0][0]
        assert "-c" in cmd
        assert "50" in cmd

    def test_count_zero_omits_c_flag(self, mock_run):
        from tools.network import tcpdump_read
        tcpdump_read(PCAP, count=0)
        cmd = mock_run.call_args[0][0]
        assert "-c" not in cmd

    def test_output_path_evidence_blocked(self):
        from tools.network import tcpdump_read
        with pytest.raises(Exception):
            tcpdump_read(PCAP, output_path="/cases/example/evidence/out.txt")


class TestTshark:
    def test_protocol_hierarchy(self, mock_run):
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            from tools.network import tshark_protocol_hierarchy
            tshark_protocol_hierarchy(PCAP)
        cmd = mock_run.call_args[0][0]
        assert "tshark" in cmd and "io,phs" in cmd

    def test_conversations_rejects_bad_proto(self):
        from tools.network import tshark_conversations
        r = tshark_conversations(PCAP, proto="bogus")
        assert r["success"] is False

    def test_ja3_missing_binary(self):
        with patch("shutil.which", return_value=None):
            from tools.network import tshark_ja3
            r = tshark_ja3(PCAP)
        assert r["success"] is False and "tshark" in r["error"]


class TestZeekSuricata:
    def test_zeek_evidence_output_blocked(self):
        from tools.network import zeek_analyze
        with pytest.raises(Exception):
            zeek_analyze(PCAP, output_dir="/cases/x/evidence/logs")

    def test_suricata_evidence_output_blocked(self):
        from tools.network import suricata_analyze
        with pytest.raises(Exception):
            suricata_analyze(PCAP, output_dir="/cases/x/evidence/logs")


class TestTcpdumpExtract:
    def test_extract_http(self, mock_run):
        from tools.network import tcpdump_extract_http
        tcpdump_extract_http(PCAP)
        cmd = mock_run.call_args[0][0]
        assert "port 80" in " ".join(cmd) or "8080" in " ".join(cmd)

    def test_extract_dns(self, mock_run):
        from tools.network import tcpdump_extract_dns
        tcpdump_extract_dns(PCAP)
        cmd = mock_run.call_args[0][0]
        assert "port 53" in " ".join(cmd) or "53" in cmd

    def test_list_connections(self, mock_run):
        from tools.network import tcpdump_list_connections
        tcpdump_list_connections(PCAP)
        cmd = mock_run.call_args[0][0]
        assert "tcpdump" in cmd
        assert "-q" in cmd


class TestNgrepSearch:
    def test_basic_search(self, mock_run):
        from tools.network import ngrep_search
        ngrep_search(PCAP, "password")
        cmd = mock_run.call_args[0][0]
        assert "ngrep" in cmd
        assert "password" in cmd

    def test_case_insensitive_flag(self, mock_run):
        from tools.network import ngrep_search
        ngrep_search(PCAP, "test", case_insensitive=True)
        cmd = mock_run.call_args[0][0]
        assert "-i" in cmd

    def test_protocol_filter(self, mock_run):
        from tools.network import ngrep_search
        ngrep_search(PCAP, "test", protocol="tcp")
        cmd = mock_run.call_args[0][0]
        assert "tcp" in cmd


class TestTcpdumpExtractIps:
    def test_extracts_unique_ips(self, mock_run):
        from tools.network import tcpdump_extract_ips
        mock_run.return_value = {
            "success": True,
            "stdout": (
                "IP 192.168.1.1.443 > 10.0.0.5.56789\n"
                "IP 192.168.1.1.443 > 10.0.0.6.56790\n"
                "IP 10.0.1.100.80 > 10.0.0.5.56791\n"
            ),
            "stderr": "",
            "exit_code": 0,
            "_atlas_call_id": 1,
        }
        r = tcpdump_extract_ips(PCAP)
        assert r["success"] is True
        assert "192.168.1.1" in r["unique_ips"]
        assert "10.0.0.5" in r["unique_ips"]
        assert r["count"] >= 3

    def test_deduplicates_ips(self, mock_run):
        from tools.network import tcpdump_extract_ips
        mock_run.return_value = {
            "success": True,
            "stdout": "192.168.1.1 192.168.1.1 192.168.1.1\n",
            "stderr": "",
            "exit_code": 0,
            "_atlas_call_id": 1,
        }
        r = tcpdump_extract_ips(PCAP)
        assert r["unique_ips"].count("192.168.1.1") == 1

    def test_addresses_beyond_the_output_cap_are_included(self, mock_run, tmp_path):
        # The executor shows the model a capped stdout but retains the whole
        # text; a beacon late in the capture is only in the retained file.
        from tools.network import tcpdump_extract_ips
        head = "IP 10.0.0.5.51000 > 10.0.0.1.53\n"
        full = tmp_path / "capture.stdout"
        full.write_text(head + "IP 10.0.0.5.51001 > 203.0.113.9.443\n" * 3)
        mock_run.return_value = {
            "success": True, "stdout": head, "stderr": "", "exit_code": 0,
            "truncated": True, "stdout_file": str(full), "_atlas_call_id": 1,
        }
        r = tcpdump_extract_ips(PCAP)
        assert "203.0.113.9" in r["unique_ips"]
        assert r["complete"] is True
        assert r["by_packets"][0]["ip"] == "10.0.0.5"
        assert {d["ip"]: d["lines"] for d in r["by_packets"]}["203.0.113.9"] == 3

    def test_truncated_without_a_retained_copy_says_so(self, mock_run):
        from tools.network import tcpdump_extract_ips
        mock_run.return_value = {
            "success": True, "stdout": "IP 10.0.0.5.1 > 10.0.0.1.2\n",
            "stderr": "", "exit_code": 0, "truncated": True, "_atlas_call_id": 1,
        }
        r = tcpdump_extract_ips(PCAP)
        assert r["complete"] is False
        assert "first part" in r["note"]


class TestPcapIdentityTimeline:
    def test_matches_jcoachj_roster_identity_before_ymsg_amy(self, mock_run):
        from tools.network import pcap_identity_timeline
        raw = {
            "success": True,
            "stdout": (
                "2008-07-21 23:01:01.000000 IP 192.168.15.4.35796 > 74.125.19.104.80: Flags [P.]\n"
                "GET /calendar/render?gausr=jcoachj%40gmail.com HTTP/1.1\r\n"
                "Host: www.google.com\r\n"
                "User-Agent: Firefox\r\n"
                "Cookie: OL_SESSION=jcoachj%40gmail.com-cal; gmailchat=jcoachj%40gmail.com/475090\r\n\r\n"
                "2008-07-21 23:09:58.000000 IP 192.168.15.4.36518 > 66.163.181.179.5050: Flags [P.]\n"
                "YMSG....1..amy789smith..216..Amy..254..Smith\n"
            ),
            "stderr": "",
            "exit_code": 0,
            "_atlas_call_id": 7,
        }

        with patch("tools.network._run_tcpdump_ascii", return_value=raw):
            r = pcap_identity_timeline(
                PCAP,
                source_ip="192.168.15.4",
                roster_names=["Amy Smith", "Johnny Coach"],
            )

        assert r["success"] is True
        assert "Johnny Coach" in r["summary"]["matched_by_person"]
        assert "jcoachj@gmail.com" in r["summary"]["matched_by_person"]["Johnny Coach"]
        assert "Amy Smith" in r["summary"]["matched_by_person"]
        johnny = [
            row for row in r["identities"]
            if "Johnny Coach" in row["roster_matches"]
        ]
        amy = [
            row for row in r["identities"]
            if "Amy Smith" in row["roster_matches"]
        ]
        assert min(row["order"] for row in johnny) < min(row["order"] for row in amy)

    def test_records_structured_wrapper_marker(self, tmp_path, mock_run):
        from core.execution_log import ExecutionLog
        from tools.network import pcap_identity_timeline
        raw = {
            "success": True,
            "stdout": (
                "2008-07-21 23:01:01.000000 IP 192.168.15.4.35796 > 74.125.19.104.80: Flags [P.]\n"
                "GET /calendar/render?gausr=jcoachj%40gmail.com HTTP/1.1\r\n"
                "Host: www.google.com\r\n\r\n"
            ),
            "stderr": "",
            "exit_code": 0,
            "_atlas_call_id": 7,
        }
        log = ExecutionLog()
        log.configure("NET-PCAP", str(tmp_path / "trace.json"), save_session=False)

        with patch("tools.network._run_tcpdump_ascii", return_value=raw), \
             patch("core.execution_log.log", log):
            r = pcap_identity_timeline(PCAP, roster_names=["Johnny Coach"])

        assert r["_atlas_call_id"] != 7
        marker = log._entries[-1]
        assert marker["type"] == "tool_call"
        assert marker["cmd"] == "<py>:net_pcap_identity_timeline"
        assert marker["input_call_ids"] == [7]


class TestTcpdumpWriteFiltered:
    def test_evidence_output_blocked(self):
        from tools.network import tcpdump_write_filtered
        with pytest.raises(Exception):
            tcpdump_write_filtered(PCAP, "/cases/example/evidence/filtered.pcap", "tcp")

    def test_safe_output_allowed(self, tmp_path, mock_run):
        from tools.network import tcpdump_write_filtered
        out = str(tmp_path / "filtered.pcap")
        tcpdump_write_filtered(PCAP, out, "host 10.0.0.1")
        cmd = mock_run.call_args[0][0]
        assert "-w" in cmd
        assert out in cmd

    def test_executor_gets_the_directory_and_root_keeps_the_write(self, tmp_path, mock_run):
        """The output file's parent is what must exist; the file itself must
        not be created as a directory. And the write happens as root, so a
        case directory the service user cannot write is no obstacle."""
        from tools.network import tcpdump_write_filtered
        out = str(tmp_path / "exports" / "filtered.pcap")
        tcpdump_write_filtered(PCAP, out, "host 10.0.0.1")
        cmd = mock_run.call_args[0][0]
        assert cmd[cmd.index("-Z") + 1] == "root"
        assert cmd[cmd.index("-w") + 1] == out
        assert mock_run.call_args[1]["output_dir"] == str(tmp_path / "exports")


class TestZeekPaths:
    def test_capture_path_is_absolute_and_program_resolved(self, tmp_path, mock_run, monkeypatch):
        """zeek runs inside the output directory, so a case-relative capture
        name must be made absolute first."""
        from tools import network
        monkeypatch.setattr("core.paths.tool_program", lambda name: "/opt/zeek/bin/zeek")
        monkeypatch.chdir(tmp_path)
        network.zeek_analyze("evidence/rhino.log", str(tmp_path / "analysis" / "zeek"))
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "/opt/zeek/bin/zeek"
        assert cmd[cmd.index("-r") + 1] == str(tmp_path / "evidence" / "rhino.log")
        assert mock_run.call_args[1]["cwd"] == str(tmp_path / "analysis" / "zeek")

    def test_missing_program_is_reported_not_retried(self, tmp_path, mock_run, monkeypatch):
        from tools import network
        monkeypatch.setattr("core.paths.tool_program", lambda name: None)
        result = network.zeek_analyze(PCAP, str(tmp_path / "analysis" / "zeek"))
        assert result["success"] is False and "zeek" in str(result.get("error", ""))
        assert not mock_run.called


class TestTcpxtractStreams:
    def test_output_dir_safe(self, tmp_path, mock_run):
        from tools.network import tcpxtract_streams
        out = str(tmp_path / "streams")
        tcpxtract_streams(PCAP, out)
        cmd = mock_run.call_args[0][0]
        assert "tcpxtract" in cmd
        assert "-o" in cmd

    def test_evidence_output_blocked(self):
        from tools.network import tcpxtract_streams
        with pytest.raises(Exception):
            tcpxtract_streams(PCAP, "/cases/example/evidence/streams")


class TestCaptureStaging:
    def test_staged_path_names_the_evidence_file(self, tmp_path):
        from pathlib import Path
        from types import SimpleNamespace
        from core.entities import artifact_tokens
        from tools.network import _capture_for_tcpdump
        src = tmp_path / "evidence" / "capture2.log"
        src.parent.mkdir()
        src.write_bytes(b"\xd4\xc3\xb2\xa1")
        stub = SimpleNamespace(case_dir=lambda: str(tmp_path))
        with patch("core.execution_log.log", stub):
            staged = _capture_for_tcpdump(str(src))
        assert staged.endswith(".pcap") and staged != str(src)
        assert tmp_path / "analysis" / "pcap_staging" in Path(staged).parents
        # The recorded command must still name the file the analyst asked for.
        assert "capture2.log" in artifact_tokens(f"tcpdump -r {staged}")
