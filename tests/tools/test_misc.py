"""Tests for tools/misc.py."""
import os
import pytest
from unittest.mock import MagicMock, patch


# Both fixtures patch through monkeypatch, so a test's own
# monkeypatch.setattr of the same name sits on the same undo stack and is
# unwound first; a patch() context would restore the real function before
# monkeypatch put the mock back, leaving it for every later test.
@pytest.fixture(autouse=True)
def mock_run(run_ok, monkeypatch):
    m = MagicMock(return_value=run_ok)
    monkeypatch.setattr("tools.misc.run", m)
    return m


@pytest.fixture(autouse=True)
def installed_programs(monkeypatch):
    """Pretend the optional forensic programs are installed.

    The wrappers resolve their program through ``core.paths.tool_program``
    and refuse cleanly when it is absent, so command-construction tests
    would otherwise assert against a machine that happens to have pdfid or
    RegRipper. The refusal itself is covered by its own test below.
    """
    monkeypatch.setattr("tools.misc.tool_program",
                        MagicMock(side_effect=lambda name, *rest: f"/usr/local/bin/{name}"))


class TestRegripper:
    # A stand-in for the installed plugin set so resolution tests don't depend
    # on /opt/regripper being present on the test host.
    IDX = {"samparse", "compname", "usbstor", "usb", "usbdevices",
           "networklist", "networkcards", "shutdown", "timezone",
           "userassist", "services", "mpmru"}

    def test_regripper_hive(self, mock_run, tmp_path):
        # Real hive: the input-kind gate refuses an invented path first.
        from tests.conftest import make_hive
        from tools.misc import regripper_hive
        regripper_hive(make_hive(tmp_path / "config" / "SYSTEM"))
        cmd = mock_run.call_args[0][0]
        assert "rip" in " ".join(cmd) or "regripper" in " ".join(cmd)

    def test_regripper_list_plugins(self, mock_run):
        from tools.misc import regripper_list_plugins
        regripper_list_plugins()
        assert mock_run.called

    # ── plugin-name resolution (root cause of a batch of plugin lookup failures) ──
    def test_resolve_exact_plugin(self):
        from tools.misc import _resolve_regripper_plugin
        r = _resolve_regripper_plugin("samparse", self.IDX)
        assert r == {"mode": "plugin", "name": "samparse"}

    def test_resolve_strips_pl_suffix_and_case(self):
        from tools.misc import _resolve_regripper_plugin
        r = _resolve_regripper_plugin("UserAssist.pl", self.IDX)
        assert r["mode"] == "plugin" and r["name"] == "userassist"

    def test_resolve_hive_keyword_to_auto(self):
        """Hive/profile names ('software','system','sam','all') are not
        plugins — they must run rip.pl -a, not fail."""
        from tools.misc import _resolve_regripper_plugin
        for kw in ("all", "software", "SYSTEM", "sam", "ntuser"):
            r = _resolve_regripper_plugin(kw, self.IDX)
            assert r["mode"] == "auto", kw

    def test_resolve_alias_corrects_name(self):
        from tools.misc import _resolve_regripper_plugin
        assert _resolve_regripper_plugin("computername", self.IDX)["name"] == "compname"
        assert _resolve_regripper_plugin("enum_usb", self.IDX)["name"] == "usbstor"
        assert _resolve_regripper_plugin("shutdowncount", self.IDX)["name"] == "shutdown"
        assert _resolve_regripper_plugin("networks", self.IDX)["name"] == "networklist"

    def test_resolve_unknown_suggests_never_autoruns(self):
        """An ambiguous/foreign name (Volatility's 'printkey') must NOT silently
        resolve to a wrong plugin — it returns suggestions for the model."""
        from tools.misc import _resolve_regripper_plugin
        r = _resolve_regripper_plugin("printkey", self.IDX)
        assert r["mode"] == "unknown"
        assert isinstance(r["suggestions"], list)
        # 'mru' must be a suggestion, not an auto-run to 'mpmru'
        r2 = _resolve_regripper_plugin("mru", self.IDX)
        assert r2["mode"] == "unknown" and "mpmru" in r2["suggestions"]

    def test_resolve_no_index_passthrough(self):
        """If the plugin dir can't be read, behave like the old code: pass the
        name straight to -p (never worse than before)."""
        from tools.misc import _resolve_regripper_plugin
        r = _resolve_regripper_plugin("anyplugin", set())
        assert r == {"mode": "plugin", "name": "anyplugin"}

    def test_hive_keyword_runs_dash_a(self, mock_run, tmp_path):
        from unittest.mock import patch
        from tests.conftest import make_hive
        from tools.misc import regripper_hive
        with patch("tools.misc._regripper_plugin_index", return_value=self.IDX):
            regripper_hive(make_hive(tmp_path / "SOFTWARE"), plugin="software")
        cmd = mock_run.call_args[0][0]
        assert "-a" in cmd and "-p" not in cmd

    def test_alias_invokes_corrected_plugin(self, mock_run, tmp_path):
        from unittest.mock import patch
        from tests.conftest import make_hive
        from tools.misc import regripper_hive
        with patch("tools.misc._regripper_plugin_index", return_value=self.IDX):
            r = regripper_hive(make_hive(tmp_path / "SYSTEM"),
                               plugin="computername")
        cmd = mock_run.call_args[0][0]
        assert cmd[-2:] == ["-p", "compname"]
        assert r["plugin_resolved"] == "compname"
        assert "plugin_note" in r

    def test_unknown_plugin_errors_without_running(self, mock_run, tmp_path):
        from unittest.mock import patch
        from tests.conftest import make_hive
        from tools.misc import regripper_hive
        with patch("tools.misc._regripper_plugin_index", return_value=self.IDX):
            r = regripper_hive(make_hive(tmp_path / "SYSTEM"),
                               plugin="printkey")
        assert r["success"] is False
        assert "not installed" in r["stderr"]
        assert isinstance(r["did_you_mean"], list)
        assert not mock_run.called  # no rip.pl subprocess for an unknown name


class TestClamScan:
    def test_clamscan_file(self, mock_run):
        from tools.misc import clamscan_file
        clamscan_file("/malware/sample.exe")
        cmd = mock_run.call_args[0][0]
        assert "clamscan" in cmd

    def test_clamscan_directory(self, mock_run, tmp_path):
        from tools.misc import clamscan_directory
        clamscan_directory(str(tmp_path))
        cmd = mock_run.call_args[0][0]
        assert "clamscan" in cmd
        assert "-r" in cmd


class TestPdfTools:
    def test_pdfid_scan(self, mock_run):
        from tools.misc import pdfid_scan
        pdfid_scan("/evidence/malicious.pdf")
        assert mock_run.called

    def test_pdf_parser_analyze(self, mock_run):
        from tools.misc import pdf_parser_analyze
        pdf_parser_analyze("/evidence/malicious.pdf")
        assert mock_run.called

    def test_pdf_parser_with_object_id(self, mock_run):
        from tools.misc import pdf_parser_analyze
        pdf_parser_analyze("/evidence/malicious.pdf", object_id=5)
        assert mock_run.called


class TestPeTools:
    def test_pe_scanner(self, mock_run, tmp_path):
        from tools.misc import pe_scanner
        blob = tmp_path / "sample.exe"
        blob.write_bytes(b"not a portable executable")
        out = pe_scanner(str(blob))
        assert out["success"] is False and "not a PE file" in out["error"]
        assert not mock_run.called

    def test_pe_carver(self, mock_run, tmp_path):
        from tools.misc import pe_carver
        pe_carver("/malware/blob.bin", str(tmp_path / "carved"))
        assert mock_run.called


class TestScheduledTasks:
    def test_parse_scheduled_tasks(self, tmp_path):
        from tools.misc import parse_scheduled_tasks
        tasks_dir = tmp_path / "Tasks"
        tasks_dir.mkdir()
        (tasks_dir / "evil_task.xml").write_text(
            '<?xml version="1.0"?><Task><Actions><Exec>'
            '<Command>powershell.exe</Command>'
            '</Exec></Actions></Task>'
        )
        r = parse_scheduled_tasks(str(tasks_dir))
        assert r["success"] is True
        assert r["task_count"] == 1

    def test_parse_scheduled_tasks_missing_dir(self):
        from tools.misc import parse_scheduled_tasks
        # os.walk on a nonexistent dir returns empty — success with 0 tasks
        r = parse_scheduled_tasks("/nonexistent/Tasks")
        assert r["task_count"] == 0


class TestUsnParser:
    def test_usnparser(self, mock_run, tmp_path, monkeypatch):
        from tools.misc import usnparser_parse
        monkeypatch.chdir(tmp_path)
        with patch("tools.misc._bin_or_warn", return_value="/venv/bin/usn.py"), \
             patch("tools.misc.assert_output_safe", lambda p: None):
            usnparser_parse("/mnt/wkstn01/$UsnJrnl")
        cmd = mock_run.call_args.args[0]
        assert cmd[0] == "/venv/bin/usn.py" and "--csv" in cmd
        assert cmd[cmd.index("-o") + 1].endswith("_usn.csv")


class TestHindsight:
    def test_hindsight_chrome(self, mock_run, tmp_path):
        from tools.misc import hindsight_chrome
        hindsight_chrome("/mnt/wkstn01/Users/jsmith/AppData/Local/Google/Chrome/User Data/Default", str(tmp_path))
        assert mock_run.called


def _seed_log_with_dair(tmp_path):
    """Helper: configure log + seed a dair_call so finding gates can be exercised."""
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    l.configure("TEST", str(tmp_path / "trace.json"))
    l.record_dair_call("Triage", "", False, "", "", "stay", "")
    return l


def _seed_log_ready_for_confirmed(tmp_path, description: str = ""):
    """Seed log with dair_call + tool_call + reason_hypothesize +
    reason_confidence_score + reason_cite_check + reason_evaluate_finding
    so all gates (dair_required / confirmed_requires_supported_evaluate /
    confidence_and_citation / hypothesize_required) are satisfied for
    CONFIRMED-tier findings.

    description: if provided, the seeded reason_confidence_score and
    reason_cite_check entries carry inputs.user_message containing the
    description string so the confidence_and_citation gate's substring match
    succeeds. Pass the exact description the test will record; the helper
    normalizes it.
    """
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    l.configure("TEST", str(tmp_path / "trace.json"))
    l.record_dair_call("Triage", "", False, "", "", "stay", "")
    tool_id = l.record_tool_call("vol.psscan", True, False, 0, 0)
    # hypothesize_required satisfaction (only matters when description
    # contains a keyword from _HYPOTHESIZE_KEYWORDS).
    l.record_reason_call("reason_hypothesize", True, "hypothesis OK", {})
    # confidence_and_citation satisfaction: matching user_message.
    _inputs = {"user_message": (description or "")[:200].lower()} if description else None
    l.record_reason_call(
        "reason_confidence_score",
        True,
        'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED", "score": 0.95}',
        {},
        inputs=_inputs,
    )
    l.record_reason_call(
        "reason_cite_check",
        True,
        'CITE_CHECK:\n{"verdict": "ALL_CITED"}',
        {},
        inputs=_inputs,
    )
    # confirmed_requires_supported_evaluate satisfaction.
    l.record_reason_call(
        "reason_evaluate_finding", True,
        "EVIDENCE SUPPORT: confirmed.\nVERDICT: SUPPORTED — evidence sound.",
        {},
    )
    return l, tool_id


class TestMissingArtifactHashAdvisory:
    """A CONFIRMED/LIKELY finding naming a malicious/dropped
    file artifact but citing no hash gets a non-blocking advisory."""

    def _f(self, desc, conf="CONFIRMED", ev=""):
        from tools.misc import _missing_artifact_hash
        return _missing_artifact_hash(desc, ev, conf)

    def test_dropped_exe_without_hash_flagged(self):
        assert self._f("Attacker dropped C:\\Windows\\Temp\\evil.exe "
                       "(Cobalt Strike beacon)") is True

    def test_carved_maldoc_without_hash_flagged(self):
        assert self._f("Malicious invoice.docm carved from unallocated") is True

    def test_hash_present_not_flagged(self):
        assert self._f("Dropped evil.exe, SHA256 "
                       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca4"
                       "95991b7852b855") is False

    def test_md5_present_not_flagged(self):
        assert self._f("Dropped evil.exe md5 "
                       "d41d8cd98f00b204e9800998ecf8427e") is False

    def test_suspected_tier_not_flagged(self):
        # advisory targets CONFIRMED/LIKELY only (custody-relevant tiers).
        assert self._f("Dropped evil.exe beacon", conf="SUSPECTED") is False

    def test_no_filename_not_flagged(self):
        # a malicious cue without a concrete file token is too vague to nudge.
        assert self._f("Lateral movement via SMB brute force") is False

    def test_benign_file_mention_not_flagged(self):
        # a filename with no malicious/drop cue is not an artifact-hash case.
        assert self._f("User opened report.docm from the Documents folder "
                       "during normal work") is False

    def test_likely_tier_flagged(self):
        assert self._f("Payload beacon.dll staged in AppData",
                       conf="LIKELY") is True

    def test_hash_in_supporting_evidence_not_flagged(self):
        assert self._f("Dropped evil.exe",
                       ev="hash_file: d41d8cd98f00b204e9800998ecf8427e") is False


class TestRecordFinding:
    def test_record_finding_returns_success(self, tmp_path):
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path, "toolx.exe timestomped")
        with patch("core.execution_log.log", l):
            r = record_finding("toolx.exe timestomped", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True
        assert r["confidence"] == "CONFIRMED"

    def test_record_finding_stores_linked_call_id(self, tmp_path):
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path, "toolx.exe timestomped")
        with patch("core.execution_log.log", l):
            record_finding("toolx.exe timestomped", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        finding_entries = [e for e in l._entries if e["type"] == "finding"]
        assert finding_entries[0]["linked_call_id"] == tid

    def test_record_finding_default_linked_call_id_zero(self, tmp_path):
        # SUSPECTED is the looser tier — no confidence_and_citation /
        # hypothesize_required checks. Documents
        # that linked_call_id defaults to 0 when omitted.
        from tools.misc import record_finding
        l = _seed_log_with_dair(tmp_path)
        with patch("core.execution_log.log", l):
            record_finding("test finding", "SUSPECTED", "vol.netscan", input_call_ids=[1])
        finding_entries = [e for e in l._entries if e["type"] == "finding"]
        assert finding_entries[0]["linked_call_id"] == 0

    def test_reason_chain_beyond_30_entries_still_satisfies_confidence_gate(self, tmp_path):
        """0-CONFIRMED under-tiering root cause:
        a valid confidence_score/cite_check aged out of the plain last-30 window
        when the analyst batched many tool calls before recording, so
        confidence_and_citation refused a correctly-evidenced finding. The
        widened reason_window keeps content-matched reason_calls in reach.
        Tested at LIKELY (exercises confidence_and_citation but not the strict
        most-recent evaluate gate)."""
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        # Neutral description (no process/C2/persistence keyword) so only
        # confidence_and_citation applies, not hypothesize_required.
        desc = "budget.xlsx present in the recycle bin"
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("net.tcpdump_read", True, False, 0, 0)
        _inputs = {"user_message": desc.lower()}
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "LIKELY", "score": 0.8}',
                             {}, inputs=_inputs)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}',
                             {}, inputs=_inputs)
        # Bury the reason chain behind 35 tool calls (> the 30-entry window).
        for i in range(35):
            l.record_tool_call(f"strings grep {i}", True, False, 0, 0)
        # dair stays recent in a real run (strict-recency gate) — the reason
        # chain is what aged out. Re-establish the DAIR window before recording.
        l.record_dair_call("Analyze", "", False, "", "", "stay", "")
        with patch("core.execution_log.log", l):
            r = record_finding(desc, "LIKELY", "net.tcpdump_read",
                               linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True, r.get("error")
        assert r["confidence"] == "LIKELY"

    def test_gate_window_does_not_widen_dair_recency(self, tmp_path):
        """gate_window adds only reason_calls — a stale dair_call outside the
        last-30 window must NOT be resurrected, or dair_required would pass on
        an aged dair_assess."""
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")  # old
        for i in range(35):
            l.record_tool_call(f"vol pslist {i}", True, False, 0, 0)
        win = l.gate_window(30)
        assert not any(e.get("type") == "dair_call" for e in win)

    def test_duplicate_description_not_re_recorded(self, tmp_path):
        # An identical (normalised) description is not appended a second time —
        # a run can record the same finding repeatedly.
        from tools.misc import record_finding
        l = _seed_log_with_dair(tmp_path)
        with patch("core.execution_log.log", l):
            r1 = record_finding("C2 at 203.0.113.19:8080", "SUSPECTED",
                                "net.tcpdump_read", input_call_ids=[1])
            r2 = record_finding("  c2 at   203.0.113.19:8080  ", "SUSPECTED",
                                "net.tcpdump_read", input_call_ids=[1])
        assert r1["success"] is True and "duplicate" not in r1
        assert r2["success"] is True and r2["duplicate"] is True
        findings = [e for e in l._entries if e["type"] == "finding"]
        assert len(findings) == 1  # only the first was appended


class TestParseEmail:
    def _write_eml(self, tmp_path, from_="alice@evil.example", return_path=None):
        rp = return_path if return_path is not None else from_
        eml = tmp_path / "msg.eml"
        eml.write_text(
            f"Return-Path: <{rp}>\r\n"
            f"From: \"Boss\" <{from_}>\r\n"
            "To: victim <bob@corp.example>\r\n"
            "Subject: invoice\r\n"
            "Message-ID: <abc@evil.example>\r\n"
            "MIME-Version: 1.0\r\n"
            'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
            "--B\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"
            "--B\r\nContent-Type: application/zip\r\n"
            'Content-Disposition: attachment; filename="p.zip"\r\n'
            "Content-Transfer-Encoding: base64\r\n\r\n"
            "UEsDBAo=\r\n--B--\r\n", encoding="utf-8")
        return str(eml)

    def test_headers_and_attachment(self, tmp_path):
        from tools.misc import parse_email
        r = parse_email(self._write_eml(tmp_path))
        assert r["success"] is True
        assert "alice@evil.example" in r["from"]
        assert r["attachment_count"] == 1
        att = r["attachments"][0]
        assert att["filename"] == "p.zip" and len(att["md5"]) == 32

    def test_spoof_mismatch_flagged(self, tmp_path):
        from tools.misc import parse_email
        eml = self._write_eml(tmp_path, from_="ceo@corp.example",
                              return_path="mailer@evil.example")
        r = parse_email(eml)
        assert r["header_provenance"]["mismatch"] is True
        assert r["header_provenance"]["notes"]

    def test_attachment_extraction_evidence_blocked(self, tmp_path):
        from tools.misc import parse_email
        eml = self._write_eml(tmp_path)
        with pytest.raises(Exception):
            parse_email(eml, extract_attachments_to="/cases/x/evidence/out")


class TestParseEmlx:
    def _write_emlx(self, tmp_path, from_="ceo@corp.example", return_path="mailer@evil.example"):
        raw = (
            f"Return-Path: <{return_path}>\r\n"
            f"From: \"CEO\" <{from_}>\r\n"
            "To: victim@corp.example\r\n"
            "Subject: urgent wire\r\n"
            "Message-ID: <abc@evil.example>\r\n"
            "\r\nplease wire funds\r\n"
        ).encode()
        emlx = tmp_path / "123.emlx"
        emlx.write_bytes(str(len(raw)).encode() + b"\n" + raw + b"<plist>ignored</plist>")
        return str(emlx)

    def test_delegates_to_parse_email_and_keeps_its_own_path(self, tmp_path):
        from tools.misc import parse_emlx
        path = self._write_emlx(tmp_path)
        r = parse_emlx(path)
        assert r["success"] is True
        assert r["eml_path"] == path  # not the deleted temp file
        assert "ceo@corp.example" in r["from"]
        assert r["header_provenance"]["mismatch"] is True

    def test_bad_first_line_rejected(self, tmp_path):
        from tools.misc import parse_emlx
        bad = tmp_path / "bad.emlx"
        bad.write_bytes(b"not-a-number\nrest")
        r = parse_emlx(str(bad))
        assert r["success"] is False
        assert "byte count" in r["error"]

    def test_temp_file_cleaned_up(self, tmp_path):
        from tools.misc import parse_emlx
        path = self._write_emlx(tmp_path)
        parse_emlx(path)
        leftover_eml = [p for p in os.listdir(tmp_path) if p.endswith(".eml")]
        assert leftover_eml == []


class TestParseMsgOle:
    def test_missing_library_degrades_gracefully(self, tmp_path, monkeypatch):
        import sys
        from tools.misc import parse_msg_ole
        monkeypatch.setitem(sys.modules, "extract_msg", None)
        msg = tmp_path / "x.msg"
        msg.write_bytes(b"whatever")
        r = parse_msg_ole(str(msg))
        assert r["success"] is False
        assert "extract-msg not installed" in r["error"]

    def test_not_an_ole_file_rejected(self, tmp_path):
        from tools.misc import parse_msg_ole
        msg = tmp_path / "not_ole.msg"
        msg.write_bytes(b"not an ole file")
        r = parse_msg_ole(str(msg))
        assert r["success"] is False
        assert "not a valid .msg" in r["error"]


class TestRecordFindingLinkedCallIdGate:
    """confirmed_requires_linked_call_id: CONFIRMED needs a non-zero linked_call_id.
    linked_call_id_must_exist: the id must point at a real trace entry."""

    def test_confirmed_with_zero_linked_call_id_refused(self, tmp_path):
        from tools.misc import record_finding
        l, _ = _seed_log_ready_for_confirmed(tmp_path, "malicious .exe")
        with patch("core.execution_log.log", l):
            r = record_finding("malicious .exe", "CONFIRMED", "ez.mftecmd", linked_call_id=0, input_call_ids=[1])
        assert r["success"] is False
        assert "linked_call_id" in r["error"]

    def test_confirmed_with_unknown_linked_call_id_refused(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "0")
        from tools.misc import record_finding
        l, _ = _seed_log_ready_for_confirmed(tmp_path, "malicious .exe")
        # Keep the fabricated id so linked_call_id_must_exist can fire.
        with patch("core.execution_log.log", l), patch(
            "tools.misc._repair_lineage_ids",
            lambda log, input_call_ids=None, linked_call_id=0, description="": (
                list(input_call_ids or []), int(linked_call_id or 0), {}),
        ):
            r = record_finding("malicious .exe", "CONFIRMED", "ez.mftecmd", linked_call_id=99999, input_call_ids=[1])
        assert r["success"] is False
        assert "99999" in r["error"]
        assert "not found" in r["error"]

    def test_confirmed_with_valid_linked_call_id_succeeds(self, tmp_path):
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path, "malicious .exe")
        with patch("core.execution_log.log", l):
            r = record_finding("malicious .exe", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True

    def test_suspected_with_zero_linked_call_id_allowed(self, tmp_path):
        # confirmed_requires_linked_call_id only restricts CONFIRMED; the
        # loosest tier may omit linked_call_id.
        from tools.misc import record_finding
        l = _seed_log_with_dair(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding("possible anomaly", "SUSPECTED", "vol.netscan", linked_call_id=0, input_call_ids=[1])
        assert r["success"] is True

    def test_suspected_with_unknown_linked_call_id_refused(self, tmp_path):
        # linked_call_id_must_exist applies to any tier when linked_call_id != 0.
        from tools.misc import record_finding
        l = _seed_log_with_dair(tmp_path)
        with patch("core.execution_log.log", l), patch(
            "tools.misc._repair_lineage_ids",
            lambda log, input_call_ids=None, linked_call_id=0, description="": (
                list(input_call_ids or []), int(linked_call_id or 0), {}),
        ):
            r = record_finding("possible anomaly", "SUSPECTED", "vol.netscan", linked_call_id=42, input_call_ids=[1])
        assert r["success"] is False
        assert "42" in r["error"]


class TestRecordFindingEvaluateVerdictGate:
    """confirmed_requires_supported_evaluate: CONFIRMED refused if most recent
    reason.evaluate_finding verdict is CHALLENGED."""

    def test_confirmed_with_recent_challenged_evaluate_refused(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_reason_call(
            "reason_evaluate_finding", True,
            "EVIDENCE SUPPORT: weak.\nVERDICT: CHALLENGED — YARA-only evidence.",
            {},
        )
        with patch("core.execution_log.log", l):
            r = record_finding("attacker tool", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert "CHALLENGED" in r["error"]
        assert r.get("evaluate_verdict") == "CHALLENGED"

    def test_confirmed_with_recent_supported_evaluate_succeeds(self, tmp_path):
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path, "attacker tool")
        with patch("core.execution_log.log", l):
            r = record_finding("attacker tool", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True

    def test_most_recent_supported_wins_over_older_challenged(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        # hypothesize_required + confidence_and_citation satisfaction
        # (description has no keyword but CONFIRMED still needs confidence
        # + cite_check).
        _ins = {"user_message": "attacker tool"}
        l.record_reason_call("reason_hypothesize", True, "hypothesis OK", {})
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}', {}, inputs=_ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}', {}, inputs=_ins)
        # Older CHALLENGED followed by newer SUPPORTED — should succeed.
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: CHALLENGED", {})
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
        with patch("core.execution_log.log", l):
            r = record_finding("attacker tool", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True

    def test_most_recent_challenged_refuses_even_with_older_supported(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: CHALLENGED", {})
        with patch("core.execution_log.log", l):
            r = record_finding("attacker tool", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert "CHALLENGED" in r["error"]

    def test_uncertain_verdict_blocks_confirmed(self, tmp_path):
        # VERDICT: UNCERTAIN is insufficient for CONFIRMED — it means the
        # reviewer could not confirm, not that they supported the claim.
        # The gate now requires an explicit SUPPORTED verdict.
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: UNCERTAIN", {})
        with patch("core.execution_log.log", l):
            r = record_finding("attacker tool", "CONFIRMED", "ez.mftecmd",
                               linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert r["gate"] == "evidence_strength"
        assert r["detail_gate"] == "confirmed_requires_supported_evaluate"
        assert "UNCERTAIN" in r["evaluate_verdict"]
        # Auto-emits self_correction just like CHALLENGED
        sc = [e for e in l._entries if e["type"] == "self_correction"]
        assert sc

    def test_auto_downgrade_can_be_disabled(self, tmp_path, monkeypatch):
        # Re-pointed at the citation gate on purpose. This test used to assert a
        # refusal on confirmed_requires_supported_evaluate with the switch off —
        # but that gate no longer downgrades at all, so the refusal happens with
        # the switch on or off and the test proved nothing about the switch.
        # confidence_and_citation is now the only gate the switch governs.
        monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "0")
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        # SUPPORTED evaluate present, so the tier passes the review gate and the
        # only thing left to fail on is the citation ritual.
        l.record_reason_call(
            "reason_evaluate_finding", True,
            "EVIDENCE SUPPORT: strong.\nVERDICT: SUPPORTED", {},
        )
        with patch("core.execution_log.log", l):
            r = record_finding(
                "attacker tool at 10.0.0.101", "CONFIRMED", "ez.mftecmd",
                linked_call_id=tid, input_call_ids=[tid],
            )
        assert r["success"] is False
        assert r.get("detail_gate") == "confidence_and_citation"
        assert r.get("tier_auto_downgraded_from") is None

    def test_evidence_lookup_reads_nested_output_not_only_stdout(self, tmp_path):
        # The subject here is the evidence lookup finding a table tool's payload
        # under `output` instead of `stdout`. It arrived asserting only
        # success + tier_auto_downgraded_from, which tested the downgrade and
        # never the lookup its name claimed — and the downgrade path it relied on
        # is gone, since a missing evaluate now refuses rather than lowering the
        # tier. So it asserts the lookup, with the tier made admissible.
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("table.table_query", True, False, 0, 0)
        # Simulate table tool payload stored under output (not stdout).
        for e in l._entries:
            if e.get("call_id") == tid:
                e["output"] = {
                    "success": True,
                    "matched_rows": 2,
                    "rows": [
                        {"RemoteIP": "10.0.0.101", "AccountName": "user01"},
                    ],
                }
                break
        desc = "user01 authenticated from 10.0.0.101"
        ins = {"user_message": desc}
        l.record_reason_call(
            "reason_evaluate_finding", True,
            "EVIDENCE SUPPORT: strong.\nVERDICT: SUPPORTED", {}, inputs=ins)
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}', {},
                             inputs=ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}', {},
                             inputs=ins)
        with patch("core.execution_log.log", l):
            r = record_finding(
                desc,
                "CONFIRMED",
                "table.table_query",
                linked_call_id=tid,
                input_call_ids=[tid],
                supporting_evidence="EDR lateral CSV row for user01",
            )
        # The payload lives only under `output`, so a stdout-only lookup would
        # refuse here on the linked-evidence gate rather than record.
        assert r["success"] is True, r
        assert r["confidence"] == "CONFIRMED"
        assert r.get("tier_auto_downgraded_from") is None

    def test_missing_evaluate_refuses_instead_of_downgrading(self, tmp_path):
        # The behaviour change, pinned on its own: a CONFIRMED request with no
        # reason.evaluate_finding at all is refused. It used to land as LIKELY,
        # and LIKELY satisfies the blocking case-question gate in
        # reason_pre_report_check — so the adversarial review was optional in
        # practice while nothing blocked on its absence.
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        with patch("core.execution_log.log", l):
            r = record_finding(
                "attacker tool at 10.0.0.101", "CONFIRMED", "ez.mftecmd",
                linked_call_id=tid, input_call_ids=[tid],
            )
        assert r["success"] is False
        assert r.get("detail_gate") == "confirmed_requires_supported_evaluate"
        assert r.get("tier_auto_downgraded_from") is None
        # The escape is named in the refusal, so a latched run is not deadlocked.
        assert "SUSPECTED" in r["error"] or "LIKELY" in r["error"], r["error"]

    def test_evaluate_matched_by_description_not_cross_contaminated(self, tmp_path):
        # Bug A regression: with two findings reviewed in one batch, a DIFFERENT
        # finding's CHALLENGED verdict (more recent) must NOT block this finding
        # whose own evaluate_finding was SUPPORTED. The gate matches the
        # evaluate by description, not by 'most recent'.
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        a_ins = {"user_message": "cron persistence root crontab evil.sh"}
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}', {}, inputs=a_ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}', {}, inputs=a_ins)
        # A's evaluate (SUPPORTED, echoes A's description)
        l.record_reason_call("reason_evaluate_finding", True,
                             "FINDING: cron persistence root crontab evil.sh\nVERDICT: SUPPORTED",
                             {}, inputs=a_ins)
        # B's evaluate (CHALLENGED, more recent, a DIFFERENT finding)
        l.record_reason_call("reason_evaluate_finding", True,
                             "FINDING: injection marker pid 488\nVERDICT: CHALLENGED",
                             {}, inputs={"user_message": "injection marker pid 488"})
        with patch("core.execution_log.log", l):
            r = record_finding("Cron persistence root crontab evil.sh", "CONFIRMED",
                               "ez.mftecmd", linked_call_id=tid,
                               tested_hypothesis_id="H0001", input_call_ids=[tid])
        assert r["success"] is True

    def test_challenged_refusal_auto_emits_self_correction(self, tmp_path):
        # Self-correction auto-emit: when CONFIRMED is refused due to CHALLENGED verdict,
        # a self_correction entry should be appended automatically.
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: CHALLENGED", {})
        with patch("core.execution_log.log", l):
            r = record_finding("overclaimed", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        sc = [e for e in l._entries if e["type"] == "self_correction"]
        assert len(sc) == 1
        # The gate uses a distinct trigger so it's distinguishable from the
        # auto-emit inside reason.evaluate_finding (which uses
        # "evaluate_challenged"). This one specifically captures "agent
        # attempted to push CONFIRMED through despite CHALLENGED verdict".
        assert sc[0]["trigger"] == "evaluate_challenged_gate_refused"


class TestRecordFindingDairGate:
    """Any finding (any tier) requires a recent dair_call."""

    def test_finding_without_any_dair_refused(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_reason_call("reason_evaluate_finding", True, "ok", {})
        with patch("core.execution_log.log", l):
            r = record_finding("CONFIRMED claim", "CONFIRMED", "ez.mftecmd", input_call_ids=[1])
        assert r["success"] is False
        assert "dair_assess" in r["error"]
        assert all(e["type"] != "finding" for e in l._entries)

    def test_suspected_without_dair_also_refused(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = record_finding("anomaly", "SUSPECTED", "vol.netscan", input_call_ids=[1])
        assert r["success"] is False
        assert "dair_assess" in r["error"]

    def test_stale_dair_beyond_30_entries_refused(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        for _ in range(31):
            l.record_reason_call("reason_hypothesize", True, "ok", {})
        with patch("core.execution_log.log", l):
            r = record_finding("anomaly", "LIKELY", "vol.netscan", input_call_ids=[1])
        assert r["success"] is False
        assert "dair_assess" in r["error"]


class TestRecordFindingEvaluateGate:
    """CONFIRMED tier additionally requires a recent reason.evaluate_finding."""

    def test_confirmed_without_recent_evaluate_refused(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        with patch("core.execution_log.log", l):
            r = record_finding("malicious .exe", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert "reason.evaluate_finding" in r["error"]
        assert all(e["type"] != "finding" for e in l._entries)

    def test_confirmed_with_recent_evaluate_succeeds(self, tmp_path):
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path, "malicious .exe")
        with patch("core.execution_log.log", l):
            r = record_finding("malicious .exe", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True

    def test_suspected_with_dair_does_not_require_evaluate(self, tmp_path):
        # SUSPECTED is the loose tier — only dair_required is checked.
        from tools.misc import record_finding
        l = _seed_log_with_dair(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding("anomaly observed", "SUSPECTED", "vol.netscan", input_call_ids=[1])
        assert r["success"] is True

    def test_stale_evaluate_beyond_30_entries_refused(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        # 31 dair_calls push the evaluate call out of the 30-entry window
        for _ in range(31):
            l.record_dair_call("Triage", "", False, "", "", "stay", "")
        with patch("core.execution_log.log", l):
            r = record_finding("malicious .exe", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert "reason.evaluate_finding" in r["error"]

    def test_evaluate_of_this_finding_beyond_30_entries_still_counts(self, tmp_path):
        """The review is tied to its finding by content: a batch of tool
        calls between reviewing and recording must not age it out. The
        anonymous most-recent fallback stays strict (test above)."""
        from tools.misc import record_finding
        desc = "budget.xlsx present in the recycle bin"
        l, tid = _seed_log_ready_for_confirmed(tmp_path, desc)
        l.record_reason_call("reason_evaluate_finding", True,
                             f"FINDING: {desc}\nVERDICT: SUPPORTED",
                             {}, inputs={"user_message": desc.lower()})
        for i in range(35):
            l.record_tool_call(f"strings grep {i}", True, False, 0, 0)
        l.record_dair_call("Analyze", "", False, "", "", "stay", "")
        with patch("core.execution_log.log", l):
            r = record_finding(desc, "CONFIRMED", "ez.mftecmd",
                               linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True, r.get("error")
        assert r["confidence"] == "CONFIRMED"


# ── New tool wrappers ─────────────────────────────────────────────────────────

class TestPffExport:
    def test_pffexport_missing_binary_returns_error(self, tmp_path, monkeypatch):
        from tools.misc import pff_export
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: None)
        out_dir = tmp_path / "exports"
        out_dir.mkdir()
        r = pff_export("/tmp/fake.pst", str(out_dir))
        assert r["success"] is False
        assert "pffexport not installed" in r["error"]

    def test_pffexport_calls_binary_when_available(self, tmp_path, monkeypatch):
        from tools.misc import pff_export
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: "/usr/bin/pffexport")
        captured = {}
        monkeypatch.setattr("tools.misc.run", lambda cmd, **kw: captured.setdefault("cmd", cmd) or {"success": True})
        out_dir = tmp_path / "exports"
        out_dir.mkdir()
        pff_export("/tmp/x.pst", str(out_dir), mode="all")
        assert captured["cmd"][0] == "/usr/bin/pffexport"
        assert "-m" in captured["cmd"]
        assert "all" in captured["cmd"]

    def test_pffexport_refuses_evidence_output_path(self):
        from tools.misc import pff_export
        import pytest
        with pytest.raises(ValueError):
            pff_export("/tmp/x.pst", "/mnt/host01/extract")


class TestReadpstExtract:
    def test_readpst_missing_binary(self, tmp_path, monkeypatch):
        from tools.misc import readpst_extract
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: None)
        out_dir = tmp_path / "exports"
        out_dir.mkdir()
        r = readpst_extract("/tmp/x.pst", str(out_dir))
        assert r["success"] is False

    def test_readpst_invokes_binary(self, tmp_path, monkeypatch):
        from tools.misc import readpst_extract
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: "/usr/bin/readpst")
        captured = {}
        monkeypatch.setattr("tools.misc.run", lambda cmd, **kw: captured.setdefault("cmd", cmd) or {"success": True})
        out_dir = tmp_path / "exports"
        out_dir.mkdir()
        readpst_extract("/tmp/x.pst", str(out_dir))
        assert "/usr/bin/readpst" == captured["cmd"][0]
        assert "-o" in captured["cmd"]


class TestDensityscout:
    def test_densityscout_missing_binary(self, monkeypatch):
        from tools.misc import densityscout_scan
        import os
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: None)
        # Also ensure the fallback path doesn't exist
        monkeypatch.setattr(os.path, "exists", lambda p: False)
        r = densityscout_scan("/tmp/x.exe")
        assert r["success"] is False


class TestChainsawHunt:
    def test_chainsaw_missing_binary(self, monkeypatch):
        from tools.misc import chainsaw_hunt
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: None)
        r = chainsaw_hunt("/tmp/evtx_dir")
        assert r["success"] is False
        assert "chainsaw not installed" in r["error"]


class TestCapaAnalyze:
    def test_capa_missing_binary(self, monkeypatch):
        from tools.misc import capa_analyze
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: None)
        r = capa_analyze("/tmp/x.exe")
        assert r["success"] is False
        assert "flare-capa" in r["error"]


class TestOlevbaScan:
    def test_olevba_missing_binary(self, monkeypatch):
        from tools.misc import olevba_scan
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: None)
        r = olevba_scan("/tmp/x.docx")
        assert r["success"] is False
        assert "oletools" in r["error"]


class TestMraptorScan:
    def test_mraptor_missing_binary(self, monkeypatch):
        from tools.misc import mraptor_scan
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: None)
        r = mraptor_scan("/tmp/x.docx")
        assert r["success"] is False


class TestBatchRun:
    def test_batch_run_empty(self):
        from tools.misc import batch_run
        r = batch_run([])
        assert r["success"] is True
        assert r["results"] == []

    def test_batch_run_runs_commands_concurrently(self, monkeypatch):
        from tools.misc import batch_run
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return {"success": True, "cmd": cmd}

        monkeypatch.setattr("tools.misc.run", fake_run)
        r = batch_run([{"cmd": ["echo", "a"]}, {"cmd": ["echo", "b"]}], max_concurrent=2)
        assert r["success"] is True
        assert len(r["results"]) == 2
        # Order preserved by index, even with concurrency
        assert r["results"][0]["cmd"] == ["echo", "a"]
        assert r["results"][1]["cmd"] == ["echo", "b"]

    def test_batch_run_rejects_invalid_cmd(self, monkeypatch):
        from tools.misc import batch_run
        # No-op fake run so the runner doesn't try real subprocess
        monkeypatch.setattr("tools.misc.run", lambda cmd, **kw: {"success": True})
        r = batch_run([{"timeout": 5}])  # missing cmd
        assert r["results"][0]["success"] is False
        assert "missing or invalid 'cmd'" in r["results"][0]["error"]

    def test_batch_run_propagates_mcp_tool_contextvar_to_workers(self, monkeypatch):
        # The middleware sets current_mcp_tool in the async thread; batch_run's
        # ThreadPoolExecutor workers must see it (copy_context) so the
        # subprocesses they spawn self-log with the right mcp_tool.
        from tools.misc import batch_run
        from core.execution_log import current_mcp_tool
        seen = []

        def fake_run(cmd, **kw):
            seen.append(current_mcp_tool.get())
            return {"success": True, "cmd": cmd}

        monkeypatch.setattr("tools.misc.run", fake_run)
        tok = current_mcp_tool.set("misc_batch_run")
        try:
            batch_run([{"cmd": ["echo", "a"]}, {"cmd": ["echo", "b"]}],
                      max_concurrent=2)
        finally:
            current_mcp_tool.reset(tok)
        assert seen == ["misc_batch_run", "misc_batch_run"]


class TestRecordAgentMessageWithFindings:
    """record_agent_message accepts an optional structured findings list and
    writes each as a finding entry through the same gate as record_finding."""

    def _seed(self, tmp_path, descriptions=None):
        """Trace seeded with all checkpoints so CONFIRMED findings pass the
        gate (dair_required + confirmed_requires_supported_evaluate +
        confidence_and_citation + hypothesize_required).

        descriptions: optional list of normalized description substrings to
        seed into the user_message of confidence_score / cite_check entries
        so the confidence_and_citation per-finding substring match succeeds.
        """
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("RAM-001", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.netscan", True, False, 0, 0,
                                  stdout_excerpt="PID 7000 -> 192.0.2.10:8080")
        l.record_reason_call("reason_hypothesize", True, "hypothesis OK", {})
        # Pack every description into the user_message so a single seeded call
        # satisfies every distinct finding's substring match.
        _msg = " | ".join(d.lower() for d in (descriptions or []))
        _ins = {"user_message": _msg} if _msg else None
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}', {}, inputs=_ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}', {}, inputs=_ins)
        l.record_reason_call(
            "reason_evaluate_finding", True,
            "VERDICT: SUPPORTED — corroborated by multiple sources.", {},
        )
        return l, tid

    def test_without_findings_matches_legacy(self, tmp_path):
        from tools.misc import record_agent_message
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("RAM-002", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = record_agent_message(content="just analysis")
        assert r["success"] is True
        assert "findings" not in r
        narr = [e for e in l._entries if e["type"] == "investigation_narration"]
        assert len(narr) == 1
        assert narr[0]["content"] == "just analysis"

    def test_ids_the_run_has_not_issued_are_refused(self, tmp_path):
        """A narration cites the results it interprets; an id the trace
        never issued is refused with the count of ids that exist, and no
        narration is written on the false edge."""
        from tools.misc import record_agent_message
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("RAM-004", str(tmp_path / "trace.json"))
        tid = l.record_tool_call("vol.netscan", True, False, 0, 0)
        with patch("core.execution_log.log", l):
            r = record_agent_message(content="analysis", input_call_ids=[tid, tid + 9])
        assert r["success"] is False and r["gate"] == "lineage_required"
        assert f"holds 1 call ids, the highest is {tid}" in r["error"]
        assert not [e for e in l._entries if e["type"] == "investigation_narration"]

    def test_disposition_is_stamped_and_records_no_finding(self, tmp_path):
        from tools.misc import record_agent_message
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("RAM-003", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = record_agent_message(
                content="Searched fw.log for 203.0.113.44: no match",
                disposition=True)
        assert r["success"] is True
        narr = [e for e in l._entries if e["type"] == "investigation_narration"]
        assert narr[0]["kind"] == "disposition"
        assert not [e for e in l._entries if e["type"] == "finding"]

    def test_with_confirmed_findings_writes_atomic(self, tmp_path):
        from tools.misc import record_agent_message
        desc = "toolx2.exe (PID 7000) is CS Beacon on LAB-FILE"
        l, tid = self._seed(tmp_path, descriptions=[desc])
        with patch("core.execution_log.log", l):
            r = record_agent_message(
                content="LAB-FILE memory shows CS Beacon on toolx2.exe.",
                input_call_ids=[tid],
                findings=[
                    {"description": desc,
                     "confidence": "CONFIRMED",
                     "linked_call_id": tid,
                     "source": "vol.netscan"},
                ],
            )
        assert r["success"] is True
        assert r["any_finding_refused"] is False
        assert len(r["findings"]) == 1
        assert r["findings"][0]["success"] is True
        # Narration + 1 finding entry in the trace
        narrs = [e for e in l._entries if e["type"] == "investigation_narration"]
        finds = [e for e in l._entries if e["type"] == "finding"]
        assert len(narrs) == 1
        assert len(finds) == 1
        assert finds[0]["confidence"] == "CONFIRMED"

    def test_gate_failures_return_per_finding(self, tmp_path):
        from tools.misc import record_agent_message
        # Seed inputs covering only the valid finding's description; the
        # invalid one fails confirmed_requires_linked_call_id before
        # confidence_and_citation anyway.
        l, tid = self._seed(tmp_path, descriptions=["valid finding"])
        with patch("core.execution_log.log", l):
            r = record_agent_message(
                content="some analysis",
                input_call_ids=[tid],
                findings=[
                    # Valid CONFIRMED — inherits input_call_ids from the message
                    {"description": "valid finding", "confidence": "CONFIRMED",
                     "linked_call_id": tid, "source": "vol.netscan"},
                    # Invalid: CONFIRMED without linked_call_id → gate refuses
                    {"description": "no link", "confidence": "CONFIRMED",
                     "linked_call_id": 0, "source": "vol.netscan"},
                ],
            )
        assert r["any_finding_refused"] is True
        assert r["findings"][0]["success"] is True
        assert r["findings"][1]["success"] is False
        # Narration still written
        narrs = [e for e in l._entries if e["type"] == "investigation_narration"]
        assert len(narrs) == 1
        # Only the valid finding ended up in the trace
        finds = [e for e in l._entries if e["type"] == "finding"]
        assert len(finds) == 1

    def test_suspected_finding_no_evaluate_required(self, tmp_path):
        # SUSPECTED tier skips confirmed_requires_supported_evaluate /
        # confidence_and_citation / hypothesize_required — only dair_required.
        from tools.misc import record_agent_message
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("RAM-003", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        with patch("core.execution_log.log", l):
            r = record_agent_message(
                content="possible anomaly",
                findings=[
                    {"description": "weak signal", "confidence": "SUSPECTED",
                     "source": "vol.netscan"},
                ],
            )
        assert r["findings"][0]["success"] is True


# ── MCP routing enforcement ──────────────────────────────────────────────────

class TestRecordFindingMcpRoutingGate:
    """mcp_routing: findings whose linked_call_id points to a raw-bash forensic-binary
    invocation are refused. The architectural-guardrail story requires
    forensic execution to flow through the typed MCP layer, not the host shell.
    """

    def _append_bash_tool_call(self, l, cmd: str) -> int:
        """Mimic the PostToolUse hook: append a tool_call entry with
        source='claude_code_bash' directly, bypassing record_tool_call (which
        doesn't accept a `source` kwarg — that field is only set by the hook).
        """
        cid = l._next_id()
        l._entries.append({
            "call_id": cid,
            "type": "tool_call",
            "ts": "2031-02-04T12:00:00Z",
            "cmd": cmd,
            "success": True,
            "truncated": False,
            "retries": 0,
            "exit_code": 0,
            "elapsed_seconds": 0.0,
            "stderr": "",
            "source": "claude_code_bash",
        })
        return cid

    def _seed_with_bash_call(self, tmp_path, cmd: str, description: str = ""):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("MCP-ROUTE", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        cid = self._append_bash_tool_call(l, cmd)
        # confirmed_requires_supported_evaluate + confidence_and_citation +
        # hypothesize_required satisfied — only mcp_routing should refuse.
        _ins = {"user_message": description.lower()} if description else None
        l.record_reason_call("reason_hypothesize", True, "hypothesis OK", {})
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}', {}, inputs=_ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}', {}, inputs=_ins)
        l.record_reason_call("reason_evaluate_finding", True,
                             "VERDICT: SUPPORTED", {})
        return l, cid

    def test_bash_vol_invocation_refuses_finding(self, tmp_path):
        from tools.misc import record_finding
        desc = "p.exe is cs beacon"
        l, cid = self._seed_with_bash_call(
            tmp_path,
            cmd="/usr/local/bin/vol -f /evidence/mem.img windows.psscan",
            description=desc,
        )
        with patch("core.execution_log.log", l):
            r = record_finding(desc, "CONFIRMED", "vol.psscan", linked_call_id=cid, input_call_ids=[1])
        assert r["success"] is False
        assert r.get("gate") == "mcp_routing"
        assert "MCP routing" in r["error"]
        assert "vol.vol_" in r.get("suggested_wrapper", "")

    def test_bash_dotnet_eztool_invocation_refuses_finding(self, tmp_path):
        from tools.misc import record_finding
        desc = "evtxecmd output anomaly"
        l, cid = self._seed_with_bash_call(
            tmp_path,
            cmd="dotnet /opt/zimmermantools/EvtxECmd/EvtxECmd.dll -f /mnt/sec.evtx",
            description=desc,
        )
        with patch("core.execution_log.log", l):
            r = record_finding(desc, "CONFIRMED", "ez.evtxecmd", linked_call_id=cid, input_call_ids=[1])
        assert r["success"] is False
        assert r.get("gate") == "mcp_routing"
        assert "EvtxECmd" in r.get("offending_cmd_excerpt", "")
        assert "ez_evtxecmd" in r.get("suggested_wrapper", "")

    def test_bash_non_forensic_command_does_not_refuse(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("MCP-ROUTE", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        # Bash command that doesn't run a forensic binary — should not trip mcp_routing.
        cid = self._append_bash_tool_call(l, "ls /cases/example-case/analysis")
        l.record_reason_call("reason_hypothesize", True, "OK", {})
        _ins = {"user_message": "harmless ls"}
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}', {}, inputs=_ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}', {}, inputs=_ins)
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
        with patch("core.execution_log.log", l):
            r = record_finding("harmless ls", "CONFIRMED", "vol.psscan", linked_call_id=cid, input_call_ids=[1])
        assert r["success"] is True

    def test_mcp_sourced_call_does_not_refuse(self, tmp_path):
        # An entry without source="claude_code_bash" (i.e. came through an
        # MCP wrapper) must NOT be refused even if the cmd would match.
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path, "toolx.exe timestomped")
        with patch("core.execution_log.log", l):
            r = record_finding("toolx.exe timestomped", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True


# ── ATT&CK technique ID auto-validation ──────────────────────────────────────

class TestRecordFindingMitreValidateGate:
    """mitre_technique_validation: T-IDs in description are validated via
    correlate.mitre_validate."""

    def test_unknown_tid_refuses_finding(self, tmp_path):
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path, "process beacon t9999.999")
        with patch("core.execution_log.log", l), \
             patch("tools.correlate.mitre_validate",
                   side_effect=lambda x, **kw: {"exists": False, "technique_id": x}):
            r = record_finding("Process beacon T9999.999", "CONFIRMED",
                               "vol.netscan", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert r.get("gate") == "evidence_strength"
        assert r.get("detail_gate") == "mitre_technique_validation"
        assert "T9999.999" in r.get("unknown_technique_ids", [])

    def test_known_tid_passes_and_records_validation(self, tmp_path):
        from tools.misc import record_finding
        desc = "wmi event subscription t1546.003"
        l, tid = _seed_log_ready_for_confirmed(tmp_path, desc)
        with patch("core.execution_log.log", l), \
             patch("tools.correlate.mitre_validate",
                   side_effect=lambda x, **kw: {
                       "exists": True, "name": "WMI Subscription",
                       "tactic": "Persistence", "technique_id": x,
                   }):
            r = record_finding("WMI Event Subscription T1546.003", "CONFIRMED",
                               "ez.evtxecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True
        assert {"technique_id": "T1546.003",
                "name": "WMI Subscription",
                "tactic": "Persistence"} in r.get("validated_techniques", [])

    def test_no_tid_no_validation_attempted(self, tmp_path):
        # Findings without any T-ID don't invoke mitre_validate.
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path, "no technique here")
        with patch("core.execution_log.log", l), \
             patch("tools.correlate.mitre_validate") as mv:
            r = record_finding("No technique here", "CONFIRMED",
                               "vol.psscan", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True
        assert mv.call_count == 0


# ── confidence_score + cite_check coverage ───────────────────────────────────

class TestRecordFindingConfidenceScoreCiteCheckGate:
    """confidence_and_citation: CONFIRMED/LIKELY require a recent
    reason.confidence_score AND reason.cite_check that reference this finding."""

    def _base(self, tmp_path):
        """dair + tool + hypothesize + SUPPORTED evaluate — dair_required /
        confirmed_requires_supported_evaluate / hypothesize_required all
        satisfied but confidence_and_citation NOT yet. Tests layer the
        confidence/cite calls on top per-case."""
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("CONF-CITE", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_reason_call("reason_hypothesize", True, "OK", {})
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
        return l, tid

    def test_confirmed_without_confidence_score_autodowngrades(
            self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "1")
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        # Seed only cite_check; missing confidence_score → downgrade path.
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}',
                             {}, inputs={"user_message": "my finding text"})
        with patch("core.execution_log.log", l):
            r = record_finding("My finding text", "CONFIRMED", "vol.psscan",
                               linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True
        assert r.get("tier_auto_downgraded_from") == "CONFIRMED"
        assert r["confidence"] in ("LIKELY", "SUSPECTED")

    def test_confirmed_without_cite_check_autodowngrades(
            self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "1")
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}',
                             {}, inputs={"user_message": "my finding text"})
        with patch("core.execution_log.log", l):
            r = record_finding("My finding text", "CONFIRMED", "vol.psscan",
                               linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True
        assert r.get("tier_auto_downgraded_from") == "CONFIRMED"

    def test_cite_check_with_uncited_claims_autodowngrades(
            self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "1")
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        _ins = {"user_message": "my finding text"}
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}', {}, inputs=_ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "UNCITED_CLAIMS_PRESENT"}',
                             {}, inputs=_ins)
        with patch("core.execution_log.log", l):
            r = record_finding("My finding text", "CONFIRMED", "vol.psscan",
                               linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True
        assert r.get("tier_auto_downgraded_from") == "CONFIRMED"

    def test_confidence_score_lower_tier_autodowngrades(
            self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "1")
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        _ins = {"user_message": "my finding text"}
        # Reviewer assigned SUSPECTED, agent requested CONFIRMED → downgrade.
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "SUSPECTED"}', {}, inputs=_ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}', {}, inputs=_ins)
        with patch("core.execution_log.log", l):
            r = record_finding("My finding text", "CONFIRMED", "vol.psscan",
                               linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True
        assert r.get("tier_auto_downgraded_from") == "CONFIRMED"
        assert r["confidence"] in ("LIKELY", "SUSPECTED")

    def test_likely_tier_also_requires_g16_or_autodowngrades(
            self, tmp_path, monkeypatch):
        # LIKELY is strict — without cite ritual, auto-downgrade to SUSPECTED.
        monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "1")
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding("My finding text", "LIKELY", "vol.psscan",
                               linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True
        assert r["confidence"] == "SUSPECTED"
        assert r.get("tier_auto_downgraded_from") == "LIKELY"

    def test_g16_anti_reuse_second_finding_autodowngrades(
            self, tmp_path, monkeypatch):
        # A single confidence_score+cite_check pair can satisfy ONE finding at
        # CONFIRMED; the duplicate auto-downgrades instead of hard-refusing.
        monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "1")
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        _ins = {"user_message": "duplicate finding text"}
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}', {}, inputs=_ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}', {}, inputs=_ins)
        with patch("core.execution_log.log", l):
            r1 = record_finding("Duplicate finding text", "CONFIRMED", "vol.psscan",
                                linked_call_id=tid, input_call_ids=[tid])
            r2 = record_finding("Duplicate finding text", "CONFIRMED", "vol.psscan",
                                linked_call_id=tid, input_call_ids=[tid])
        assert r1["success"] is True
        # Second may be duplicate-short-circuit or autodowngrade — either lands.
        assert r2["success"] is True
        assert r2.get("duplicate") or r2.get("tier_auto_downgraded_from") == "CONFIRMED"


class TestRecordFindingInlineSupportingEvidence:
    """R1 fast path: passing supporting_evidence inline runs a DETERMINISTIC
    citation check and skips the reason.confidence_score + reason.cite_check
    model round-trips entirely."""

    def _base(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("INLINE", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.netscan", True, False, 0, 0)
        l.record_reason_call("reason_hypothesize", True, "OK", {})
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
        return l, tid

    def test_inline_evidence_satisfies_gate_without_reason_calls(self, tmp_path):
        import json as _json
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        # Seed a minimal MITRE table so the T-ID gate doesn't depend on the
        # machine-local ~/cases/.common cache (absent on CI runners).
        mitre_path = tmp_path / "mitre_techniques.json"
        mitre_path.write_text(_json.dumps({"techniques": {"T1071.001": {
            "name": "Application Layer Protocol: Web Protocols",
            "tactic": "command-and-control"}}}))
        from tools.mitre import _load_json
        _load_json.cache_clear()
        # NO confidence_score / cite_check seeded — the inline path replaces them.
        with patch("core.execution_log.log", l), \
             patch("tools.correlate.DEFAULT_MITRE_PATH", str(mitre_path)):
            r = record_finding(
                "C2 beacon to 203.0.113.10:8080 (T1071.001)", "CONFIRMED",
                "velo.netstat", linked_call_id=tid, tested_hypothesis_id="H1",
                input_call_ids=[tid],
                supporting_evidence="NetstatEnriched: 203.0.113.10:8080 ESTABLISHED. "
                                    "Technique T1071.001 web protocols.")
        assert r["success"] is True
        # provenance recorded
        finding = [e for e in l._entries if e["type"] == "finding"][-1]
        assert finding.get("citation_mode") == "deterministic"

    def test_inline_uncited_claim_autodowngrades(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "1")
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding(
                "Beacon to 8.8.8.8 with hash deadbeefdeadbeefdeadbeefdeadbeef",
                "CONFIRMED", "velo.netstat", linked_call_id=tid,
                tested_hypothesis_id="H1", input_call_ids=[tid],
                supporting_evidence="NetstatEnriched: 203.0.113.10:8080 ESTABLISHED.")
        # Values not in tool output cannot be auto-cited → land as SUSPECTED.
        assert r["success"] is True
        assert r["confidence"] == "SUSPECTED"
        assert r.get("tier_auto_downgraded_from") == "CONFIRMED"

    def test_inline_uncited_claim_refused_when_autodowngrade_off(
            self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "0")
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding(
                "Beacon to 8.8.8.8 with hash deadbeefdeadbeefdeadbeefdeadbeef",
                "CONFIRMED", "velo.netstat", linked_call_id=tid,
                tested_hypothesis_id="H1", input_call_ids=[tid],
                supporting_evidence="NetstatEnriched: 203.0.113.10:8080 ESTABLISHED.")
        assert r["success"] is False
        assert r.get("detail_gate") == "confidence_and_citation"
        uncited = " ".join(r.get("uncited_claims", []))
        assert "8.8.8.8" in uncited
        assert "deadbeef" in uncited.lower()

    def test_likely_inline_evidence_no_eval_or_reason_calls(self, tmp_path):
        # LIKELY needs neither evaluate nor confidence/cite when evidence is inline.
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("INLINE", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.netscan", True, False, 0, 0)
        with patch("core.execution_log.log", l):
            r = record_finding(
                "Masquerade /tmp/.kworkerd is a copy of /bin/sleep", "LIKELY",
                "sha256sum", linked_call_id=tid, tested_hypothesis_id="H1",
                input_call_ids=[tid],
                supporting_evidence="paths /tmp/.kworkerd and /bin/sleep hash-match.")
        assert r["success"] is True


class TestRecordFindingGateLinkageAlwaysStamped:
    """Audit-linkage regression: findings must
    carry gated_by_* foreign keys whenever a description-matched reason_call
    exists — including on the deterministic fast path, on SUSPECTED/UNCONFIRMED
    tiers, and for evaluate_finding on non-CONFIRMED tiers."""

    def _base(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("LINKAGE", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_reason_call("reason_hypothesize", True, "OK", {})
        return l, tid

    def _last_finding(self, l):
        return [e for e in l._entries if e["type"] == "finding"][-1]

    def test_fast_path_stamps_matching_reason_calls(self, tmp_path):
        # Inline supporting_evidence takes the deterministic path, but the
        # agent ALSO ran confidence_score/cite_check/evaluate for this finding
        # — the FKs must land on the entry, not be dropped by the early return.
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        desc = "Masquerade /tmp/.kworkerd is a copy of /bin/sleep"
        _ins = {"user_message": desc.lower()}
        ev_cid = l.record_reason_call("reason_evaluate_finding", True,
                                      "VERDICT: SUPPORTED", {}, inputs=_ins)
        cs_cid = l.record_reason_call("reason_confidence_score", True,
                                      'CONFIDENCE_SCORE:\n{"tier": "LIKELY"}',
                                      {}, inputs=_ins)
        cc_cid = l.record_reason_call("reason_cite_check", True,
                                      'CITE_CHECK:\n{"verdict": "ALL_CITED"}',
                                      {}, inputs=_ins)
        with patch("core.execution_log.log", l):
            r = record_finding(
                desc, "LIKELY", "sha256sum", linked_call_id=tid,
                tested_hypothesis_id="H1", input_call_ids=[tid],
                supporting_evidence="paths /tmp/.kworkerd and /bin/sleep hash-match.")
        assert r["success"] is True
        finding = self._last_finding(l)
        assert finding.get("citation_mode") == "deterministic"
        assert finding.get("gated_by_confidence_call_id") == cs_cid
        assert finding.get("gated_by_cite_check_call_id") == cc_cid
        assert finding.get("gated_by_evaluate_call_id") == ev_cid

    def test_suspected_tier_stamps_matching_reason_calls(self, tmp_path):
        # SUSPECTED isn't gated on the checks, but if they were run for this
        # finding the audit chain must still be recorded.
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        desc = "Possible staging directory at /var/tmp/.cache"
        _ins = {"user_message": desc.lower()}
        cs_cid = l.record_reason_call("reason_confidence_score", True,
                                      'CONFIDENCE_SCORE:\n{"tier": "SUSPECTED"}',
                                      {}, inputs=_ins)
        cc_cid = l.record_reason_call("reason_cite_check", True,
                                      'CITE_CHECK:\n{"verdict": "ALL_CITED"}',
                                      {}, inputs=_ins)
        with patch("core.execution_log.log", l):
            r = record_finding(desc, "SUSPECTED", "fs.listdir",
                               linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True
        finding = self._last_finding(l)
        assert finding.get("gated_by_confidence_call_id") == cs_cid
        assert finding.get("gated_by_cite_check_call_id") == cc_cid

    def test_likely_stamps_matched_evaluate_even_when_challenged(self, tmp_path):
        # A CHALLENGED evaluate followed by an honest LIKELY downgrade is
        # exactly the review-of-record the audit trail should show.
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        desc = "Masquerade /tmp/.kworkerd is a copy of /bin/sleep"
        ev_cid = l.record_reason_call(
            "reason_evaluate_finding", True, "VERDICT: CHALLENGED", {},
            inputs={"user_message": desc.lower()})
        with patch("core.execution_log.log", l):
            r = record_finding(
                desc, "LIKELY", "sha256sum", linked_call_id=tid,
                tested_hypothesis_id="H1", input_call_ids=[tid],
                supporting_evidence="paths /tmp/.kworkerd and /bin/sleep hash-match.")
        assert r["success"] is True
        assert self._last_finding(l).get("gated_by_evaluate_call_id") == ev_cid

    def test_non_confirmed_does_not_link_unrelated_evaluate(self, tmp_path):
        # No most-recent fallback on the non-CONFIRMED stamp path: an evaluate
        # that reviewed a DIFFERENT finding must not be claimed as this
        # finding's review.
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        l.record_reason_call(
            "reason_evaluate_finding", True, "VERDICT: SUPPORTED", {},
            inputs={"user_message": "a completely different finding entirely"})
        with patch("core.execution_log.log", l):
            r = record_finding(
                "Masquerade /tmp/.kworkerd is a copy of /bin/sleep", "LIKELY",
                "sha256sum", linked_call_id=tid, tested_hypothesis_id="H1",
                input_call_ids=[tid],
                supporting_evidence="paths /tmp/.kworkerd and /bin/sleep hash-match.")
        assert r["success"] is True
        assert "gated_by_evaluate_call_id" not in self._last_finding(l)


# ── hypothesize trigger ──────────────────────────────────────────────────────

class TestRecordFindingHypothesizeGate:
    """hypothesize_required: CONFIRMED/LIKELY findings mentioning process/
    service/persistence/C2/lateral-movement require a recent
    reason.hypothesize call."""

    def _base_no_hypothesize(self, tmp_path, desc: str):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("HYP-REQ", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        _ins = {"user_message": desc.lower()}
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}', {}, inputs=_ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}', {}, inputs=_ins)
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
        return l, tid

    def test_process_keyword_without_hypothesize_refused(self, tmp_path):
        from tools.misc import record_finding
        desc = "rogue process pid 7000 c2 to internal host"
        l, tid = self._base_no_hypothesize(tmp_path, desc)
        with patch("core.execution_log.log", l):
            r = record_finding(desc, "CONFIRMED", "vol.psscan", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert r.get("gate") == "evidence_strength"
        assert r.get("detail_gate") == "hypothesize_required"

    def test_tested_hypothesis_id_carve_out(self, tmp_path):
        # Passing tested_hypothesis_id satisfies hypothesize_required without
        # a separate hypothesize call (proves the hypothesize→finding loop
        # completed).
        from tools.misc import record_finding
        desc = "rogue process pid 7000 c2 to internal host"
        l, tid = self._base_no_hypothesize(tmp_path, desc)
        with patch("core.execution_log.log", l):
            r = record_finding(desc, "CONFIRMED", "vol.psscan",
                               linked_call_id=tid, tested_hypothesis_id="H0001", input_call_ids=[tid])
        assert r["success"] is True

    def test_no_keyword_no_hypothesize_required(self, tmp_path):
        # File-existence finding without trigger keywords skips hypothesize_required.
        from tools.misc import record_finding
        desc = "evidence file checksum matches reference"
        l, tid = self._base_no_hypothesize(tmp_path, desc)
        with patch("core.execution_log.log", l):
            r = record_finding(desc, "CONFIRMED", "hash.verify", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True


# ── export_execution_log requires pre_report_check ───────────────────────────

class TestExportRequiresPreReportCheck:
    """pre_report_check_required: misc.export_execution_log refuses unless the
    latest reason.pre_report_check returned READY_TO_REPORT: true and is not
    stale (no more than PRE_REPORT_STALE_TOOL_CALLS evidence-affecting tool
    calls after it)."""

    def test_check_survives_dair_churn(self, tmp_path):
        """DAIR/reasoning entries after a passing check must not expire it
."""
        from tools.misc import export_execution_log
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("EXPORT", str(tmp_path / "trace.json"))
        l.record_dair_call("Report", "", False, "", "", "stay", "")
        l.record_reason_call("reason_pre_report_check", True,
                             "READY_TO_REPORT: true\nBLOCKING_ISSUES (0): none", {})
        for _ in range(60):
            l.record_dair_call("Report", "", False, "", "", "stay", "")
        with patch("core.execution_log.log", l), \
             patch("tools.misc.assert_output_safe", lambda *a, **kw: None):
            r = export_execution_log(str(tmp_path / "out"))
        assert r["success"] is True

    def test_check_stale_after_substantive_work(self, tmp_path):
        """Evidence-affecting tool calls after the check DO make it stale."""
        from tools.misc import export_execution_log, PRE_REPORT_STALE_TOOL_CALLS
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("EXPORT", str(tmp_path / "trace.json"))
        l.record_dair_call("Report", "", False, "", "", "stay", "")
        l.record_reason_call("reason_pre_report_check", True,
                             "READY_TO_REPORT: true\nBLOCKING_ISSUES (0): none", {})
        for _ in range(PRE_REPORT_STALE_TOOL_CALLS + 1):
            l.record_tool_call(cmd="strings -a evidence.bin", success=True,
                               truncated=False, retries=0, exit_code=0)
        with patch("core.execution_log.log", l), \
             patch("tools.misc.assert_output_safe", lambda *a, **kw: None):
            r = export_execution_log(str(tmp_path / "out"))
        assert r["success"] is False
        assert r.get("gate") == "pre_report_check_required"
        assert r.get("stale_tool_calls_since_check", 0) > PRE_REPORT_STALE_TOOL_CALLS

    def test_missing_pre_report_check_refused(self, tmp_path, monkeypatch):
        from tools.misc import export_execution_log
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("EXPORT", str(tmp_path / "trace.json"))
        l.record_dair_call("Report", "", False, "", "", "stay", "")
        with patch("core.execution_log.log", l), \
             patch("tools.misc.assert_output_safe", lambda *a, **kw: None):
            r = export_execution_log(str(tmp_path / "out"))
        assert r["success"] is False
        assert r.get("gate") == "pre_report_check_required"
        assert r.get("missing_check") == "reason_pre_report_check"

    def test_pre_report_check_not_ready_refused(self, tmp_path):
        from tools.misc import export_execution_log
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("EXPORT", str(tmp_path / "trace.json"))
        l.record_dair_call("Report", "", False, "", "", "stay", "")
        l.record_reason_call("reason_pre_report_check", True,
                             "READY_TO_REPORT: false\nBLOCKING_ISSUES (1): ...", {})
        with patch("core.execution_log.log", l), \
             patch("tools.misc.assert_output_safe", lambda *a, **kw: None):
            r = export_execution_log(str(tmp_path / "out"))
        assert r["success"] is False
        assert r.get("gate") == "pre_report_check_required"
        assert "false" in r.get("pre_report_conclusion", "").lower()

    def test_write_final_report_stays_refused_until_ready(self, tmp_path):
        """Second write after pre_report false stays refused — finish
        blockers and re-check; no partial-report unlock."""
        from tools.misc import write_final_report
        from core.execution_log import ExecutionLog
        out = tmp_path / "reports" / "CASE_report.md"
        out.parent.mkdir(parents=True)
        l = ExecutionLog()
        l.configure("PARTIAL", str(tmp_path / "trace.json"))
        l.record_dair_call("Report", "", False, "", "", "stay", "")
        l.record_reason_call(
            "reason_pre_report_check", True,
            "READY_TO_REPORT: false\nBLOCKING_ISSUES (1): MITRE unsupported",
            {},
        )
        with patch("core.execution_log.log", l), \
             patch("tools.misc.assert_output_safe", lambda *a, **kw: None), \
             patch("tools.misc._case_has_beliefs", return_value=False):
            r1 = write_final_report(str(out), "# First attempt\n")
            assert r1["success"] is False
            assert r1.get("gate") == "pre_report_check_required"
            assert "partial_retry_available" not in r1
            assert "Do NOT retry" in (r1.get("error") or "")
            r2 = write_final_report(str(out), "# Still blocked\n")
            assert r2["success"] is False
            assert r2.get("gate") == "pre_report_check_required"
            assert not out.exists()
            l.record_reason_call(
                "reason_pre_report_check", True,
                "READY_TO_REPORT: true\nBLOCKING_ISSUES (0): none",
                {},
            )
            r3 = write_final_report(str(out), "# Full report\n")
        assert r3["success"] is True
        assert r3.get("partial") is not True
        assert out.read_text(encoding="utf-8").startswith("# Full report\n")

    def test_pre_report_check_ready_passes(self, tmp_path):
        from tools.misc import export_execution_log
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("EXPORT", str(tmp_path / "trace.json"))
        l.record_dair_call("Report", "", False, "", "", "stay", "")
        l.record_reason_call("reason_pre_report_check", True,
                             "READY_TO_REPORT: true\nBLOCKING_ISSUES (0): none", {})
        with patch("core.execution_log.log", l), \
             patch("tools.misc.assert_output_safe", lambda *a, **kw: None):
            r = export_execution_log(str(tmp_path / "out"))
        assert r["success"] is True


class TestWriteFinalReportRequiresPreReportCheck:
    """Final report writes use the same pre-report gate as trace export."""

    def test_missing_pre_report_check_refused(self, tmp_path):
        from tools.misc import write_final_report
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("REPORT", str(tmp_path / "trace.json"))
        l.record_dair_call("Report", "", False, "", "", "stay", "")
        out = tmp_path / "reports" / "report.md"
        with patch("core.execution_log.log", l):
            r = write_final_report(str(out), "# Report\n")
        assert r["success"] is False
        assert r.get("gate") == "pre_report_check_required"
        assert not out.exists()

    def test_pre_report_check_not_ready_refused(self, tmp_path):
        from tools.misc import write_final_report
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("REPORT", str(tmp_path / "trace.json"))
        l.record_dair_call("Report", "", False, "", "", "stay", "")
        l.record_reason_call("reason_pre_report_check", True,
                             "READY_TO_REPORT: false\nBLOCKING_ISSUES (1): ...", {})
        out = tmp_path / "reports" / "report.md"
        with patch("core.execution_log.log", l):
            r = write_final_report(str(out), "# Report\n")
        assert r["success"] is False
        assert r.get("gate") == "pre_report_check_required"
        assert not out.exists()

    def test_pre_report_check_ready_writes(self, tmp_path):
        from tools.misc import write_final_report
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("REPORT", str(tmp_path / "trace.json"))
        l.record_dair_call("Report", "", False, "", "", "stay", "")
        l.record_reason_call("reason_pre_report_check", True,
                             "READY_TO_REPORT: true\nBLOCKING_ISSUES (0): none", {})
        out = tmp_path / "reports" / "report.md"
        with patch("core.execution_log.log", l):
            r = write_final_report(str(out), "# Report\n")
        assert r["success"] is True
        assert out.read_text().startswith("# Report\n")
        assert r.get("_atlas_call_id")


class TestWriteCaseDocument:
    """Custom analyst extracts — no pre_report / projection gates."""

    def test_writes_under_reports_without_gates(self, tmp_path):
        from tools.misc import write_case_document
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("CHAT", str(tmp_path / "trace.json"))
        out = tmp_path / "reports" / "sites_extract.md"
        with patch("core.execution_log.log", l), \
             patch("tools.misc.assert_output_safe", lambda *a, **kw: None):
            r = write_case_document(
                str(out),
                "## A\n\nFinding C0004\n",
                title="Remote sites",
            )
        assert r["success"] is True
        assert r.get("kind") == "analyst_document"
        text = out.read_text(encoding="utf-8")
        assert text.startswith("# Remote sites\n")
        assert "C0004" in text

    def test_relative_path_resolves_against_case(self, tmp_path):
        from tools.misc import write_case_document
        from core.execution_log import ExecutionLog
        (tmp_path / "analysis").mkdir()
        (tmp_path / "reports").mkdir()
        l = ExecutionLog()
        # Trace under analysis/ → case_dir() walks up to tmp_path.
        l.configure("CHAT", str(tmp_path / "analysis" / "trace.json"),
                    save_session=False)
        with patch("core.execution_log.log", l), \
             patch("tools.misc.assert_output_safe", lambda *a, **kw: None):
            r = write_case_document(
                "reports/extract.md",
                "body only\n",
            )
        assert r["success"] is True
        assert (tmp_path / "reports" / "extract.md").read_text() == "body only\n"

    def test_empty_content_refused(self, tmp_path):
        from tools.misc import write_case_document
        r = write_case_document(str(tmp_path / "reports" / "x.md"), "  \n")
        assert r["success"] is False
        assert r.get("gate") == "empty_content"

    def test_path_outside_case_output_dirs_refused(self, tmp_path):
        from tools.misc import write_case_document
        r = write_case_document(str(tmp_path / "scratch" / "x.md"), "hello\n")
        assert r["success"] is False
        assert r.get("gate") == "output_path_unsafe"


def test_person_username_variants_include_initial_last_initial():
    from tools.misc import knowns_pattern_generate

    r = knowns_pattern_generate(["Johnny Coach"], "person_username")

    assert r["success"] is True
    assert "jcoachj" in r["all_terms"]


class TestClearCaseRunMemoryGuard:
    """clear_case_run must never delete the Claude Code assistant's own memory
    when the case dir is the Atlas repo root (case dir == project dir)."""

    def _isolated_home(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        real_expanduser = os.path.expanduser

        def fake_expanduser(p):
            if p == "~" or p.startswith("~/"):
                return str(home) + p[1:]
            return real_expanduser(p)

        monkeypatch.setattr(os.path, "expanduser", fake_expanduser)
        return home

    def _seed_memory(self, home, case_dir):
        encoded = str(case_dir).replace("/", "-")  # mirror the tool's encoding
        mem = home / ".claude" / "projects" / encoded / "memory"
        mem.mkdir(parents=True)
        (mem / "MEMORY.md").write_text("keep me", encoding="utf-8")
        return mem

    def test_repo_root_case_preserves_assistant_memory(self, tmp_path, monkeypatch):
        from tools.misc import clear_case_run
        import tools.misc as misc
        home = self._isolated_home(tmp_path, monkeypatch)
        case = tmp_path / "repo"
        (case / "analysis").mkdir(parents=True)
        (case / "analysis" / "old.json").write_text("x", encoding="utf-8")
        monkeypatch.setattr(misc, "_ATLAS_REPO_ROOT", os.path.realpath(str(case)))
        mem = self._seed_memory(home, case)

        r = clear_case_run(str(case))

        assert (mem / "MEMORY.md").exists()          # memory preserved
        assert r["memory_cleared"] is False
        assert "repo root" in r["memory_skipped_reason"]
        assert not (case / "analysis" / "old.json").exists()  # case still cleared

    def test_normal_case_clears_its_memory(self, tmp_path, monkeypatch):
        from tools.misc import clear_case_run
        import tools.misc as misc
        home = self._isolated_home(tmp_path, monkeypatch)
        case = tmp_path / "cases" / "nitroba"
        (case / "analysis").mkdir(parents=True)
        monkeypatch.setattr(misc, "_ATLAS_REPO_ROOT", os.path.realpath(str(tmp_path / "elsewhere")))
        mem = self._seed_memory(home, case)

        r = clear_case_run(str(case))

        assert not (mem / "MEMORY.md").exists()       # case memory cleared
        assert r["memory_cleared"] is True
        assert r["memory_skipped_reason"] == ""

    def test_clear_memory_false_preserves_memory(self, tmp_path, monkeypatch):
        from tools.misc import clear_case_run
        import tools.misc as misc
        home = self._isolated_home(tmp_path, monkeypatch)
        case = tmp_path / "cases" / "nitroba"
        (case / "analysis").mkdir(parents=True)
        monkeypatch.setattr(misc, "_ATLAS_REPO_ROOT", os.path.realpath(str(tmp_path / "elsewhere")))
        mem = self._seed_memory(home, case)

        r = clear_case_run(str(case), clear_memory=False)

        assert (mem / "MEMORY.md").exists()
        assert r["memory_cleared"] is False
        assert r["memory_skipped_reason"] == "clear_memory=False"


class TestClearCaseRunMountSafety:
    """clear_case_run must never rmtree a case tree that still has a forensic
    mount under it (an rmtree over a live mount orphans the kernel mount and
    can leave the case dir ENOENT with the trace unrecoverable). Unmount
    innermost-first; refuse if any survive."""

    def _proc_with(self, tmp_path, mountpoints):
        lines = [f"/dev/loop0 {mp} ntfs ro,norecovery 0 0" for mp in mountpoints]
        f = tmp_path / "proc_mounts"
        f.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return str(f)

    def test_refuses_clear_when_mount_cannot_be_unmounted(self, tmp_path, monkeypatch):
        from tools.misc import clear_case_run
        case = tmp_path / "cases" / "szechuan-sauce"
        (case / "analysis").mkdir(parents=True)
        (case / "analysis" / "old.json").write_text("keep", encoding="utf-8")
        base = os.path.realpath(str(case))
        proc = self._proc_with(tmp_path, [f"{base}/mnt/ewf_dc01"])
        monkeypatch.setattr("core.mounts._PROC_MOUNTS", proc)

        # every umount attempt fails → mount stays registered
        with patch("core.executor.run",
                   return_value={"success": False, "stderr": "target is busy"}):
            r = clear_case_run(str(case))

        assert r["success"] is False
        assert r["cleared_count"] == 0
        assert f"{base}/mnt/ewf_dc01" in r["mounts_remaining"]
        assert any("still mounted" in e for e in r["errors"])
        # the tree was NOT destroyed over the live mount
        assert (case / "analysis" / "old.json").exists()

    def test_unmounts_then_clears(self, tmp_path, monkeypatch):
        from tools.misc import clear_case_run
        case = tmp_path / "cases" / "szechuan-sauce"
        (case / "analysis").mkdir(parents=True)
        (case / "analysis" / "old.json").write_text("x", encoding="utf-8")
        base = os.path.realpath(str(case))
        proc = self._proc_with(tmp_path, [f"{base}/mnt/ewf_dc01"])
        monkeypatch.setattr("core.mounts._PROC_MOUNTS", proc)

        def fake_run(cmd, **kw):
            # a successful umount drops the entry from /proc/mounts
            self._proc_with(tmp_path, [])
            return {"success": True, "stderr": ""}

        with patch("core.executor.run", side_effect=fake_run):
            r = clear_case_run(str(case), clear_memory=False)

        assert r["success"] is True
        assert r["unmounted"] == [f"{base}/mnt/ewf_dc01"]
        assert not (case / "analysis" / "old.json").exists()   # now cleared

    def test_no_mounts_clears_normally(self, tmp_path, monkeypatch):
        from tools.misc import clear_case_run
        case = tmp_path / "cases" / "nitroba"
        (case / "analysis").mkdir(parents=True)
        (case / "analysis" / "old.json").write_text("x", encoding="utf-8")
        proc = self._proc_with(tmp_path, ["/mnt/unrelated"])
        monkeypatch.setattr("core.mounts._PROC_MOUNTS", proc)

        r = clear_case_run(str(case), clear_memory=False)

        assert r["success"] is True
        assert r["unmounted"] == []
        assert not (case / "analysis" / "old.json").exists()


class TestClearCaseRunResetsLog:
    """clear_case_run must reset the in-process execution-log singleton and
    drop a clear marker — not just delete files. Deleting the on-disk trace
    alone left the dead run's entries in memory (they re-flushed on the next
    record_*) and let a concurrent process resume them."""

    def _isolate_home(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        real = os.path.expanduser
        monkeypatch.setattr(
            os.path, "expanduser",
            lambda p: str(home) + p[1:] if p == "~" or p.startswith("~/") else real(p),
        )

    def test_clear_resets_singleton_and_writes_marker(self, tmp_path, monkeypatch):
        import core.execution_log as elog
        from tools.misc import clear_case_run
        self._isolate_home(tmp_path, monkeypatch)
        case = tmp_path / "cases" / "ws01"
        (case / "analysis").mkdir(parents=True)
        trace = str(case / "analysis" / "WS01_trace.json")
        elog.log.configure("WS01", trace, save_session=False)
        elog.log.record_finding("dead-run finding", "CONFIRMED")
        assert len(elog.log._entries) == 1

        r = clear_case_run(str(case), clear_memory=False)

        assert r["in_process_log_reset"] is True
        assert r["clear_marker"] and os.path.exists(r["clear_marker"])
        # In-memory dead-run state gone; nothing to re-flush or resume.
        assert elog.log._entries == []
        assert elog.log._path is None
        assert elog.log._case_id is None


class TestClearCaseRunResetsCoverageFloor:
    """Probed/answered ledger statuses belong to the trace
    that recorded them — which clear_case_run deletes. A 'fresh' run must
    re-earn its coverage floor, not inherit a pre-satisfied degraded-exit
    gate (a fresh run could otherwise exit hollow on turn 1)."""

    def test_clear_resets_ledger_statuses(self, tmp_path, monkeypatch):
        import json
        from tools.misc import clear_case_run
        from core.coverage_ledger import (
            build_coverage_ledger, coverage_stats, load_ledger, mark_paths,
            ready_for_degraded_exit,
        )
        case = tmp_path / "cases" / "fresh-floor"
        (case / "analysis").mkdir(parents=True)
        (case / "evidence").mkdir()
        (case / ".atlas").mkdir()
        (case / "evidence" / "vpn_logons.csv").write_text("u,t\n",
                                                         encoding="utf-8")
        (case / ".atlas" / "evidence_inventory.json").write_text(
            json.dumps({"complete": True, "summary": {
                "high_value_parsed": ["evidence/vpn_logons.csv"]}}),
            encoding="utf-8")
        (case / ".atlas" / "evidence_profile.json").write_text(
            json.dumps({
                "files": [{"path": "evidence/vpn_logons.csv",
                           "class": "tabular"}],
                "file_count": 1, "counts": {"tabular": 1},
                "absent_classes": [], "present_classes": ["tabular"],
                "samples": {},
            }),
            encoding="utf-8")
        build_coverage_ledger(case)
        mark_paths(case, ["evidence/vpn_logons.csv"], status="probed")
        assert ready_for_degraded_exit(case)

        r = clear_case_run(str(case), clear_memory=False)

        assert r["success"] is True
        stats = coverage_stats(load_ledger(case))
        assert stats["probed"] == 0
        assert stats["unseen"] == stats["total"] > 0
        assert not ready_for_degraded_exit(case)
        assert any("coverage_ledger" in c for c in r["cleared"])


class TestTierLanguageLint:
    """Prose tier words contradicting the confidence field draw a non-fatal
    warning ('X confirmed: …' findings tiered LIKELY)."""

    def test_contradicting_tier_word_warns(self, tmp_path):
        from tools.misc import record_finding
        l = _seed_log_with_dair(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding("Email channel confirmed: 7 emails exchanged",
                               "SUSPECTED", "misc.parse_email", input_call_ids=[1])
        assert r["success"] is True  # non-fatal: still records
        assert "CONFIRMED" in r["tier_language_warning"]
        assert "SUSPECTED" in r["tier_language_warning"]

    def test_matching_tier_word_passes(self, tmp_path):
        from tools.misc import record_finding
        l = _seed_log_with_dair(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding("Beacon activity suspected on host A",
                               "SUSPECTED", "net.zeek", input_call_ids=[1])
        assert r["success"] is True
        assert "tier_language_warning" not in r

    def test_no_tier_words_passes(self, tmp_path):
        from tools.misc import record_finding
        l = _seed_log_with_dair(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding("USB serial 4C53 first seen 2015-03-23",
                               "SUSPECTED", "ez.recmd", input_call_ids=[1])
        assert r["success"] is True
        assert "tier_language_warning" not in r


class TestMissingProgramsAreReportedNotCrashed:
    """Six tools were invoked from a hardcoded /usr/local/bin path that the
    installer never wrote, so the manifest advertised them and the model
    spent a call on "No such file or directory"."""

    @pytest.mark.parametrize("tool_name,call", [
        ("misc.pdfid_scan", lambda: __import__(
            "tools.misc", fromlist=["pdfid_scan"]).pdfid_scan("/x/doc.pdf")),
        ("misc.pdf_parser_analyze", lambda: __import__(
            "tools.misc", fromlist=["pdf_parser_analyze"]).pdf_parser_analyze("/x/doc.pdf")),
        ("misc.pe_carver", lambda: __import__(
            "tools.misc", fromlist=["pe_carver"]).pe_carver("/x/b.bin", "/tmp/out")),
        ("misc.hindsight_chrome", lambda: __import__(
            "tools.misc", fromlist=["hindsight_chrome"]).hindsight_chrome("/x/Default", "/tmp/o")),
    ])
    def test_absent_program_refuses_with_a_reason(self, mock_run, tool_name, call):
        with patch("tools.misc.tool_program", return_value=None):
            res = call()
        assert res["success"] is False
        assert res.get("gate") == "program_missing"
        assert "not installed" in res["error"]
        assert res["hint"], "the refusal has to say what to do instead"
        assert not mock_run.called, "nothing may be executed when it is absent"

    def test_the_manifest_agrees_with_the_wrappers(self):
        """Availability is resolved the same way in both places."""
        from tools.tool_capabilities import EXTERNAL_BINARIES
        for tool in ("misc.pdfid_scan", "misc.pdf_parser_analyze",
                     "misc.pe_carver", "misc.hindsight_chrome"):
            assert tool in EXTERNAL_BINARIES, f"{tool} advertises an uninstalled program"


class TestChainsawOutputShape:
    def test_csv_mode_reports_the_files_it_wrote_not_the_directory(self, mock_run, tmp_path):
        """chainsaw --csv treats --output as a directory and writes one file
        per rule source into it. Reporting the directory sent the next
        table.* call into a "that is a directory" refusal."""
        from tools.misc import chainsaw_hunt

        out = tmp_path / "hunt_results.csv"      # what the model passes
        out.mkdir()                              # what chainsaw makes of it
        (out / "sigma.csv").write_text("timestamp,detections\n1,x\n", encoding="utf-8")
        (out / "notes.txt").write_text("ignored", encoding="utf-8")
        mock_run.return_value = {"success": True, "stdout": "", "stderr": "",
                                 "exit_code": 0, "truncated": False, "cmd": "chainsaw"}

        with patch("tools.misc._bin_or_warn", return_value="/usr/bin/chainsaw"), \
             patch("tools.misc._chainsaw_rules_dir", return_value=str(tmp_path / "sigma")), \
             patch("tools.misc._chainsaw_mapping_for", return_value=None), \
             patch("tools.misc.assert_output_safe", return_value=None):
            res = chainsaw_hunt(str(tmp_path / "evtx"), output_path=str(out))

        assert res["artifact_paths"] == [str(out / "sigma.csv")]
        assert "sigma.csv" in res["note"]


class TestRecordingAWithdrawnFindingAgain:
    def test_the_words_of_a_withdrawn_claim_are_not_a_duplicate(self, tmp_path, monkeypatch):
        """Withdrawal retires the assertion; saying it again is a new one,
        gated afresh, not a pointer at the retired record."""
        from unittest.mock import patch
        from core.claim_graph import supersede
        from core.execution_log import ExecutionLog
        from tools.misc import record_finding
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
        (tmp_path / "analysis").mkdir()
        l = ExecutionLog()
        l.configure("DUP", str(tmp_path / "analysis" / "trace.json"), save_session=False)
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("<py>:misc_list_evidence_dir", True, False, 0, 0,
                                 stdout_excerpt="notes.txt")
        with patch("core.execution_log.log", l), \
             patch.object(l, "case_dir", return_value=str(tmp_path)), \
             patch("tools.misc.tool_program", side_effect=lambda name, *rest: f"/usr/local/bin/{name}"):
            first = record_finding("notes.txt is present in the export", "SUSPECTED",
                                   "misc.list_evidence_dir", linked_call_id=tid,
                                   input_call_ids=[tid])
            assert first["success"] and first.get("claim_id")
            again = record_finding("notes.txt is present in the export", "SUSPECTED",
                                   "misc.list_evidence_dir", linked_call_id=tid,
                                   input_call_ids=[tid])
            assert again.get("duplicate") is True
            assert supersede(str(tmp_path), first["claim_id"],
                             reason="the export listing was of another case's folder")["success"]
            third = record_finding("notes.txt is present in the export", "SUSPECTED",
                                   "misc.list_evidence_dir", linked_call_id=tid,
                                   input_call_ids=[tid])
        assert third["success"] and not third.get("duplicate")
        assert third["claim_id"] != first["claim_id"]


class TestRecordFindingIndicators:
    """Typed rows travel with the finding: checked against the cited
    output, stamped on the trace entry, carried to the claim mirror."""

    def test_rows_the_cited_output_shows_are_kept_and_the_rest_named(self, tmp_path):
        from tools.misc import record_finding
        l = _seed_log_with_dair(tmp_path)
        tid = l.record_tool_call("net.pcap_conversations", True, False, 0, 0,
                                 stdout_excerpt="10.0.0.5 -> 198.51.100.7:443 tls 2031-02-04 10:41:03 UTC svc.exe")
        with patch("core.execution_log.log", l):
            r = record_finding("svc.exe on WS01 opened a TLS session to 198.51.100.7", "SUSPECTED",
                               "net.pcap_conversations", input_call_ids=[tid], host="WS01",
                               indicators=[{"type": "ip", "value": "198.51.100.7", "side": "attacker",
                                            "first_seen": "2031-02-04T10:41:03Z"},
                                           {"type": "file", "value": "svc.exe", "side": "attacker"},
                                           {"type": "ip", "value": "198.51.100.9", "side": "attacker"}])
        assert r["success"] is True
        kept = {x["value"]: x for x in r["indicators_kept"]}
        assert set(kept) == {"198.51.100.7", "svc.exe"}
        assert kept["198.51.100.7"]["first_seen"].startswith("2031-02-04 10:41:03")
        assert r["indicators_dropped"][0]["value"] == "198.51.100.9"
        from core.claim_graph import load_graph
        node = next(n for n in load_graph(l.case_dir())["nodes"].values() if n.get("kind") == "claim")
        assert {x["value"] for x in node["indicators"]} == {"198.51.100.7", "svc.exe"}

    def test_a_finding_without_rows_is_recorded_as_before(self, tmp_path):
        from tools.misc import record_finding
        l = _seed_log_with_dair(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding("test finding", "SUSPECTED", "vol.netscan", input_call_ids=[1])
        assert r["success"] and "indicators_kept" not in r and "indicators_dropped" not in r
