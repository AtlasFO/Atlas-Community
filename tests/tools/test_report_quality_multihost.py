"""Report-quality lint + multi-host support.

Covers the client-facing report lint on write_final_report, the structured
host field on findings, host-aware finding dedup, evidence_ref stamping on
tool calls, killchain per_host buckets, and the pre-report multi-host
estate-synthesis warning.
"""
from unittest.mock import patch

from core.execution_log import ExecutionLog


def _log(tmp_path, case="MULTIHOST"):
    l = ExecutionLog()
    l.configure(case, str(tmp_path / "trace.json"))
    l.record_dair_call("Report", "", False, "", "", "stay", "")
    return l


def _report_ready_log(tmp_path):
    l = _log(tmp_path)
    l.record_reason_call("reason_pre_report_check", True,
                         "READY_TO_REPORT: true\nBLOCKING_ISSUES (0): none", {})
    return l


# ── host field on findings ────────────────────────────────────────────────────

class TestFindingHostField:
    def test_host_round_trip_into_trace_and_markdown(self, tmp_path):
        l = _log(tmp_path)
        l.record_finding("PsExec execution on dc01", "LIKELY",
                         source="ez.evtxecmd", host="dc01")
        entry = [e for e in l._entries if e["type"] == "finding"][0]
        assert entry["host"] == "dc01"
        assert "host: dc01" in l.to_markdown()

    def test_host_omitted_leaves_entry_unchanged(self, tmp_path):
        l = _log(tmp_path)
        l.record_finding("finding without host", "SUSPECTED")
        entry = [e for e in l._entries if e["type"] == "finding"][0]
        assert "host" not in entry

    def test_wrapper_passes_host_and_returns_it(self, tmp_path):
        from tools.misc import record_finding
        l = _log(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding("ransom note dropped", "SUSPECTED",
                               input_call_ids=[1], host="WS01")
        assert r["success"] is True
        assert r["host"] == "WS01"
        entry = [e for e in l._entries if e["type"] == "finding"][0]
        assert entry["host"] == "WS01"

    def test_same_description_different_host_not_deduped(self, tmp_path):
        from tools.misc import record_finding
        l = _log(tmp_path)
        with patch("core.execution_log.log", l):
            r1 = record_finding("ransom note dropped", "SUSPECTED",
                                input_call_ids=[1], host="WS01")
            r2 = record_finding("ransom note dropped", "SUSPECTED",
                                input_call_ids=[1], host="filesrv01")
        assert "duplicate" not in r1 and "duplicate" not in r2
        assert len([e for e in l._entries if e["type"] == "finding"]) == 2

    def test_same_description_same_host_deduped(self, tmp_path):
        from tools.misc import record_finding
        l = _log(tmp_path)
        with patch("core.execution_log.log", l):
            record_finding("ransom note dropped", "SUSPECTED",
                           input_call_ids=[1], host="WS01")
            r2 = record_finding("  Ransom note   dropped ", "SUSPECTED",
                                input_call_ids=[1], host="ws01")
        assert r2["duplicate"] is True
        assert len([e for e in l._entries if e["type"] == "finding"]) == 1

    def test_untagged_finding_in_tagged_trace_warns(self, tmp_path):
        from tools.misc import record_finding
        l = _log(tmp_path)
        with patch("core.execution_log.log", l):
            record_finding("PsExec on dc01", "SUSPECTED",
                           input_call_ids=[1], host="dc01")
            r = record_finding("event logs cleared", "SUSPECTED",
                               input_call_ids=[1])
        assert r["success"] is True
        assert "dc01" in r["host_tag_warning"]


# ── evidence_ref on tool calls ────────────────────────────────────────────────

class TestEvidenceRef:
    def test_explicit_param_stamped(self, tmp_path):
        l = _log(tmp_path)
        cid = l.record_tool_call("mmls image", True, False, 0, 0,
                                 evidence_ref="evidence/ws01.raw")
        entry = [e for e in l._entries if e.get("call_id") == cid][0]
        assert entry["evidence_ref"] == "evidence/ws01.raw"

    def test_contextvar_fallback(self, tmp_path):
        from core.execution_log import current_evidence_ref
        l = _log(tmp_path)
        tok = current_evidence_ref.set("mnt/host01/Windows")
        try:
            cid = l.record_tool_call("fls -r", True, False, 0, 0)
        finally:
            current_evidence_ref.reset(tok)
        entry = [e for e in l._entries if e.get("call_id") == cid][0]
        assert entry["evidence_ref"] == "mnt/host01/Windows"

    def test_extractor_matches_evidence_and_mount_paths(self):
        from core.middleware import _extract_evidence_ref
        assert _extract_evidence_ref(
            {"image_path": "/case/evidence/ws01.raw"}
        ).startswith("/evidence/") or "evidence/" in _extract_evidence_ref(
            {"image_path": "/case/evidence/ws01.raw"})
        assert "mnt/host01" in _extract_evidence_ref(
            {"hive": "mnt/host01/Windows/System32/config/SYSTEM"})
        assert _extract_evidence_ref({"pattern": "ransom", "max_results": 5}) == ""

    def test_extractor_matches_bare_image_extension(self):
        from core.middleware import _extract_evidence_ref
        assert _extract_evidence_ref({"image": "/data/corp-ws01-memory.img"})


# ── killchain per_host buckets ────────────────────────────────────────────────

class TestKillchainPerHost:
    def _seed(self, tmp_path):
        l = _log(tmp_path)
        t1486 = [{"technique_id": "T1486", "name": "Data Encrypted for Impact",
                  "tactic": "impact"}]
        t1021 = [{"technique_id": "T1021.001", "name": "RDP",
                  "tactic": "lateral movement"}]
        l.record_finding("mass encryption on WS01", "CONFIRMED",
                         host="WS01",
                         gate_metadata={"validated_techniques": t1486})
        l.record_finding("inbound RDP on dc01", "LIKELY", host="dc01",
                         gate_metadata={"validated_techniques": t1021})
        l.record_finding("untagged unmapped observation", "SUSPECTED")
        return l

    def test_per_host_buckets_present_when_hosts_tagged(self, tmp_path):
        from tools.correlate import killchain_timeline
        l = self._seed(tmp_path)
        with patch("core.execution_log.log", l):
            r = killchain_timeline(infer_unlabeled=False)
        assert r["success"] is True
        assert set(r["per_host"]) == {"WS01", "dc01", "unattributed"}
        assert r["per_host"]["WS01"][0]["technique_id"] == "T1486"
        assert r["per_host"]["dc01"][0]["technique_id"] == "T1021.001"
        assert r["stats"]["hosts"] == 3

    def test_no_per_host_key_for_single_host_untagged_trace(self, tmp_path):
        from tools.correlate import killchain_timeline
        l = _log(tmp_path)
        l.record_finding("untagged finding", "SUSPECTED")
        with patch("core.execution_log.log", l):
            r = killchain_timeline(infer_unlabeled=False)
        assert "per_host" not in r


# ── write_final_report lint ───────────────────────────────────────────────────

_NOISY_REPORT = """# Report

## 2.2 Execution
The registry parser failed with an access error on its temp directory —
worked around by reading the hive directly.

## Evidence Gaps Affecting Conclusions
PECmd not installed in this analysis environment — TOOLX.EXE path unrecoverable,
binary ID stays LIKELY.
"""

_SCOPE_REPORT = """# Report

## 2 Findings
Ransomware T1486 encrypted 1,000 files. Lateral movement to the domain
controller via RDP was observed across other hosts.

## 5 Recommended Actions
1. Sweep hosts for the ransom note pattern.
2. Block the sender address.
"""

_CLEAN_REPORT = """# Report

## 2 Findings
Ransomware T1486 encrypted 1,000 files (MFTECmd $MFT parse). Lateral movement
to the domain controller via RDP was observed.

## Evidence Gaps Affecting Conclusions
PECmd unavailable in this environment — binary ID stays LIKELY.

## 5 Recommended Actions
1. Containment/isolation decision for the affected segment.
2. Domain-wide credential hygiene incl. krbtgt reset consideration.
3. Backup integrity verification before restore.
"""

# Host reports: host-scoped recommendations only (estate items live elsewhere).
_CLEAN_HOST_REPORT = """# Report

## 2 Findings
Ransomware T1486 encrypted 1,000 files (MFTECmd $MFT parse).

## Evidence Gaps Affecting Conclusions
PECmd unavailable in this environment — binary ID stays LIKELY.

## 5 Recommended Actions
1. Preserve forensic image and increase Security.evtx size limit.
2. See Estate Report for estate-wide recommendations.
"""


class TestWriteFinalReportLint:
    def test_tool_noise_outside_gaps_defers_then_writes(self, tmp_path):
        from tools.misc import write_final_report
        l = _report_ready_log(tmp_path)
        out = tmp_path / "reports" / "report.md"
        with patch("core.execution_log.log", l):
            r1 = write_final_report(str(out), _NOISY_REPORT)
            assert r1["success"] is False
            assert r1["gate"] == "report_lint"
            assert any("tool_noise_in_findings" in w
                       for w in r1["lint_warnings"])
            assert not out.exists()
            r2 = write_final_report(str(out), _NOISY_REPORT)
        assert r2["success"] is True
        assert out.exists()
        assert any("tool_noise_in_findings" in w for w in r2["lint_warnings"])

    def test_lint_deferral_does_not_stale_pre_report_gate(self, tmp_path):
        from tools.misc import write_final_report
        l = _report_ready_log(tmp_path)
        out = tmp_path / "reports" / "report.md"
        with patch("core.execution_log.log", l):
            write_final_report(str(out), _NOISY_REPORT)
            r2 = write_final_report(str(out), _NOISY_REPORT)
        assert r2.get("gate") != "pre_report_check_required"
        assert r2["success"] is True

    def test_noise_inside_gaps_section_allowed(self, tmp_path):
        from tools.misc import _report_lint
        gaps_only = ("# Report\n\n## Evidence Gaps Affecting Conclusions\n"
                     "PECmd not installed in this analysis environment — "
                     "binary ID stays LIKELY.\n")
        assert _report_lint(gaps_only) == []

    def test_estate_scope_warning_on_local_recommendations(self, tmp_path):
        from tools.misc import _report_lint
        # Estate reports still require estate-scoped recommendations.
        warnings = _report_lint(
            _SCOPE_REPORT,
            output_path="reports/CASE_estate_report.md",
        )
        assert any("recommendations_scope" in w for w in warnings)

    def test_host_report_rejects_estate_recommendations(self, tmp_path):
        from tools.misc import _report_lint
        host_rpt = (
            "# Report\n\n## Findings\nProbed.\n\n## Recommendations\n"
            "- Containment and isolation of all hosts\n"
            "- Domain-wide credential reset including krbtgt\n"
        )
        warnings = _report_lint(
            host_rpt,
            output_path="reports/CASE_ws02_report.md",
        )
        assert any("host_vs_estate_recommendations" in w for w in warnings)

    def test_clean_report_writes_first_call(self, tmp_path):
        from tools.misc import write_final_report
        l = _report_ready_log(tmp_path)
        out = tmp_path / "reports" / "report.md"
        with patch("core.execution_log.log", l):
            r = write_final_report(str(out), _CLEAN_REPORT)
        assert r["success"] is True
        assert "lint_warnings" not in r
        written = out.read_text()
        # The analyst's body is written through byte-for-byte — that was the
        # point of the old `== _CLEAN_REPORT` equality, and it still holds.
        assert written.startswith(_CLEAN_REPORT)
        # What is new: the assembler appends a pointer to the curated timeline.
        # Asserted explicitly rather than relaxing the check to a substring, so
        # a future addition to the tail cannot slip in unnoticed.
        appended = written[len(_CLEAN_REPORT):]
        assert "## Master Timeline" in appended
        assert "master_timeline.tsv" in appended
        assert appended.strip().count("## ") == 1

    def test_multiple_reports_after_one_passing_check(self, tmp_path):
        """Per-host + estate reports: one pre_report_check covers them all."""
        from tools.misc import write_final_report
        l = _report_ready_log(tmp_path)
        host_paths = [tmp_path / "reports" / n for n in
                      ("CASE_ws01_report.md", "CASE_dc01_report.md")]
        estate = tmp_path / "reports" / "CASE_estate_report.md"
        with patch("core.execution_log.log", l):
            results = (
                [write_final_report(str(p), _CLEAN_HOST_REPORT)
                 for p in host_paths]
                + [write_final_report(str(estate), _CLEAN_REPORT)]
            )
        assert all(r["success"] for r in results)
        assert all(p.exists() for p in host_paths + [estate])


class TestPerHostReportCompleteness:
    """The estate report is the completeness checkpoint: a host that carries
    findings but has no per-host report defers the estate write once."""

    def _seed_findings(self, tmp_path, hosts):
        l = _report_ready_log(tmp_path)
        for i, h in enumerate(hosts):
            l.record_finding(f"finding on {h}", "LIKELY",
                             source="strings.strings_grep", host=h)
        return l

    def test_estate_defers_when_host_report_missing(self, tmp_path):
        from tools.misc import write_final_report
        reports = tmp_path / "reports"
        reports.mkdir()
        # vm-02 has a report on disk; vm-01 has a finding but no report.
        (reports / "CASE_vm-02_report.md").write_text(_CLEAN_HOST_REPORT)
        l = self._seed_findings(tmp_path, ["vm-02", "vm-01"])
        estate = reports / "CASE_estate_report.md"
        with patch("core.execution_log.log", l):
            r1 = write_final_report(str(estate), _CLEAN_REPORT)
            assert r1["success"] is False
            assert r1["gate"] == "report_lint"
            assert any("missing_per_host_reports" in w and "vm-01" in w
                       for w in r1["lint_warnings"])
            assert "vm-02" not in " ".join(
                w for w in r1["lint_warnings"]
                if "missing_per_host_reports" in w)
            assert not estate.exists()
            # Second call writes regardless (bounded — cannot deadlock).
            r2 = write_final_report(str(estate), _CLEAN_REPORT)
        assert r2["success"] is True
        assert estate.exists()

    def test_estate_clean_when_all_host_reports_present(self, tmp_path):
        from tools.misc import write_final_report
        reports = tmp_path / "reports"
        reports.mkdir()
        (reports / "CASE_vm-02_report.md").write_text(_CLEAN_HOST_REPORT)
        (reports / "CASE_vm-01_report.md").write_text(_CLEAN_HOST_REPORT)
        l = self._seed_findings(tmp_path, ["vm-02", "vm-01"])
        estate = reports / "CASE_estate_report.md"
        with patch("core.execution_log.log", l):
            r = write_final_report(str(estate), _CLEAN_REPORT)
        assert r["success"] is True
        assert estate.exists()
        assert "lint_warnings" not in r

    def test_per_host_report_never_triggers_check(self, tmp_path):
        """A per-host report write is not the estate checkpoint — no warning
        even when other hosts lack reports."""
        from tools.misc import write_final_report
        reports = tmp_path / "reports"
        reports.mkdir()
        l = self._seed_findings(tmp_path, ["vm-02", "vm-01"])
        out = reports / "CASE_vm-02_report.md"
        with patch("core.execution_log.log", l):
            r = write_final_report(str(out), _CLEAN_HOST_REPORT)
        assert r["success"] is True
        assert "lint_warnings" not in r

    def test_no_host_findings_estate_writes_clean(self, tmp_path):
        """Single-host / untagged case: estate report writes first call."""
        from tools.misc import write_final_report
        reports = tmp_path / "reports"
        reports.mkdir()
        l = _report_ready_log(tmp_path)  # no findings recorded
        estate = reports / "CASE_estate_report.md"
        with patch("core.execution_log.log", l):
            r = write_final_report(str(estate), _CLEAN_REPORT)
        assert r["success"] is True
        assert estate.exists()


# ── pre_report_check multi-host warning ───────────────────────────────────────

class TestPreReportMultiHostWarning:
    def _seed(self, tmp_path, synth_conclusion):
        l = _log(tmp_path)
        l.record_reason_call("reason_plan", True, "plan", {})
        l.record_reason_call("reason_hypothesize", True, "h", {})
        l.record_tool_call("<py>:coverage_coverage_report", True, False, 0, 0)
        l.record_finding("encryption event", "CONFIRMED", host="WS01")
        l.record_finding("inbound RDP", "LIKELY", host="dc01")
        l.record_reason_call("reason_synthesize", True, synth_conclusion, {})
        return l

    def test_warns_when_synthesis_lacks_estate_structure(self, tmp_path):
        from tools.reasoning import reason_pre_report_check
        l = self._seed(tmp_path, "Timeline reconstructed. TTPs mapped.")
        with patch("core.execution_log.log", l):
            r = reason_pre_report_check()
        assert any("estate" in w.lower() and "ws01" in w.lower()
                   for w in r["warnings"])

    def test_silent_when_synthesis_has_per_host_disposition(self, tmp_path):
        from tools.reasoning import reason_pre_report_check
        l = self._seed(tmp_path,
                       "Per-host disposition: WS01 encrypted, dc01 "
                       "exposed. Cross-host timeline follows.")
        with patch("core.execution_log.log", l):
            r = reason_pre_report_check()
        assert not any("estate-level structure" in w for w in r["warnings"])

    def test_silent_for_single_host_trace(self, tmp_path):
        from tools.reasoning import reason_pre_report_check
        l = _log(tmp_path)
        l.record_reason_call("reason_synthesize", True, "single host", {})
        l.record_finding("encryption event", "CONFIRMED", host="WS01")
        with patch("core.execution_log.log", l):
            r = reason_pre_report_check()
        assert not any("estate-level structure" in w for w in r["warnings"])
