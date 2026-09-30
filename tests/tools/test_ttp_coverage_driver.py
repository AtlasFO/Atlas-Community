"""Tests for the case-blind TTP-coverage driver.

Coverage stays single-digit when a gate blocks only at ZERO mapped
techniques and nothing fires during Analyze. The driver has four layers: a DAIR mid-run nudge, per-finding
coverage_report metrics, a per-finding pre_report escalation, and a
relevance annotation that keeps valid-but-irrelevant stamping from gaming
the gates.
"""
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from tools import dair


@pytest.fixture
def clean_trace():
    from core.execution_log import log
    saved = list(log._entries)
    log._entries.clear()
    yield log
    log._entries.clear()
    log._entries.extend(saved)


def _finding(desc, confidence="CONFIRMED", call_id=1, validated=None):
    e = {"type": "finding", "call_id": call_id, "description": desc,
         "confidence": confidence}
    if validated is not None:
        e["validated_techniques"] = validated
    return e


UNMAPPED_ATTACK = [
    _finding("PsExec lateral movement to WS01", call_id=11),
    _finding("toolx.exe ransomware encrypted the share", call_id=12),
]


class TestTtpNudgePredicate:
    def test_fires_in_analyze_with_unmapped_attack_findings(self, clean_trace):
        clean_trace._entries.extend(UNMAPPED_ATTACK)
        assert dair._ttp_mapping_lagging("Analyze", "") is True

    def test_fires_when_leaving_for_report(self, clean_trace):
        clean_trace._entries.extend(UNMAPPED_ATTACK)
        assert dair._ttp_mapping_lagging("Collect", "Report") is True

    def test_silent_in_triage(self, clean_trace):
        clean_trace._entries.extend(UNMAPPED_ATTACK)
        assert dair._ttp_mapping_lagging("Triage", "") is False

    def test_silent_when_findings_mapped(self, clean_trace):
        clean_trace._entries.extend([
            _finding("PsExec lateral movement (T1021.002)", call_id=11),
            _finding("toolx.exe ransomware (T1486)", call_id=12),
        ])
        assert dair._ttp_mapping_lagging("Analyze", "") is False

    def test_suspected_findings_do_not_count(self, clean_trace):
        clean_trace._entries.extend([
            _finding("possible backdoor beacon", "SUSPECTED", call_id=11),
            _finding("possible exfiltration", "SUSPECTED", call_id=12),
        ])
        assert dair._ttp_mapping_lagging("Analyze", "") is False

    def test_single_unmapped_below_threshold(self, clean_trace):
        clean_trace._entries.append(UNMAPPED_ATTACK[0])
        assert dair._ttp_mapping_lagging("Analyze", "") is False


class TestAttackFindingVocabBlindSpot:
    """Exploitation-phrased findings carrying a
    validated technique must count as attack-shaped even when no attack
    vocabulary noun matches, so coverage is not 0/0 and the gate engages."""

    # Finding text with no malware/C2/exfil noun in it.
    _EXPLOIT_DESC = ("The web server access log shows an unauthenticated "
                     "request to the admin console followed by a new "
                     "administrator session")
    _T1190 = [{"technique_id": "T1190", "name": "Exploit Public-Facing "
               "Application", "tactic": "Initial Access"}]

    def test_vocab_miss_but_technique_present_is_attack_shaped(self):
        from tools.reasoning import is_attack_finding, ATTACK_VOCAB_RE
        f = _finding(self._EXPLOIT_DESC, "LIKELY", validated=self._T1190)
        # Precondition: the vocab regex genuinely does not match this text.
        assert not ATTACK_VOCAB_RE.search(self._EXPLOIT_DESC)
        assert is_attack_finding(f) is True

    def test_vocab_miss_no_technique_not_attack_shaped(self):
        from tools.reasoning import is_attack_finding
        f = _finding(self._EXPLOIT_DESC, "LIKELY")
        assert is_attack_finding(f) is False

    def test_technique_carrier_is_never_unmapped(self):
        # A technique-carrying finding joins the mapped set, never the
        # unmapped set — the fix cannot make the block fire more aggressively.
        from tools.reasoning import (is_attack_finding,
                                     finding_carries_technique)
        f = _finding(self._EXPLOIT_DESC, "LIKELY", validated=self._T1190)
        assert is_attack_finding(f) and finding_carries_technique(f)

    def test_suspected_technique_carrier_is_attack_shaped(self):
        # A validated technique implies
        # attack-shaped at ANY tier — the carrier is mapped by construction,
        # so admitting it can never grow the unmapped set. The tier bar
        # remains for vocab-only matches (next test).
        from tools.reasoning import is_attack_finding
        f = _finding(self._EXPLOIT_DESC, "SUSPECTED", validated=self._T1190)
        assert is_attack_finding(f) is True

    def test_suspected_vocab_only_finding_still_excluded(self):
        # Expanding the vocab-only clause below CONFIRMED/LIKELY would push
        # unmapped SUSPECTED findings into the gate population and make the
        # pre-report block fire more aggressively — keep the tier bar there.
        from tools.reasoning import is_attack_finding
        f = _finding("Malware beaconing to C2 over exfil channel", "SUSPECTED")
        assert is_attack_finding(f) is False

    def test_coverage_counts_exploit_finding_as_mapped(self, clean_trace, tmp_path):
        from tools.coverage import coverage_report
        # Per-test path under tmp_path, not a shared /tmp hardcode: on a
        # multi-user box /tmp is sticky-bitted, so os.replace() over a
        # cov-other-trace.json another account left behind fails with EPERM.
        clean_trace.configure("COV-OTHER", str(tmp_path / "cov-other-trace.json"))
        clean_trace._entries.append(
            _finding(self._EXPLOIT_DESC, "LIKELY", call_id=11,
                     validated=self._T1190))
        r = coverage_report()
        assert r["finding_mapping"]["attack_findings"] == 1
        assert r["finding_mapping"]["mapped"] == 1
        assert r["finding_mapping"]["unmapped_call_ids"] == []


class TestCoverageReportMapping:
    @pytest.fixture
    def cov_log(self, tmp_path):
        import core.execution_log as elog
        saved = list(elog.log._entries)
        elog.log._entries.clear()
        yield elog.log
        elog.log._entries.clear()
        elog.log._entries.extend(saved)

    def _run(self):
        from tools.coverage import coverage_report
        fn = getattr(coverage_report, "fn", coverage_report)
        return fn()

    def test_finding_mapping_lists_unmapped_call_ids(self, cov_log):
        cov_log._entries.extend([
            _finding("toolx.exe ransomware (T1486)", call_id=5),
            _finding("PsExec lateral movement", call_id=7),
            _finding("credential dumping on DC01", call_id=9),
        ])
        r = self._run()
        assert r["finding_mapping"]["attack_findings"] == 3
        assert r["finding_mapping"]["mapped"] == 1
        assert r["finding_mapping"]["unmapped_call_ids"] == [7, 9]
        assert r["targets"]["meets_mapping"] is True  # 2 unmapped tolerated
        assert "attack-shaped findings mapped" in r["summary"]

    def test_targets_flag_mapping_violation(self, cov_log):
        cov_log._entries.extend([
            _finding(f"attack tools staged on host{i}", call_id=10 + i)
            for i in range(4)
        ])
        r = self._run()
        assert r["finding_mapping"]["mapped"] == 0
        assert r["targets"]["meets_mapping"] is False

    def test_distinct_tactics_from_validated_channel(self, cov_log):
        cov_log._entries.append(_finding(
            "toolx.exe ransomware deployed", call_id=5,
            validated=[{"technique_id": "T1486", "name": "Data Encrypted",
                        "tactic": "Impact"}]))
        r = self._run()
        assert r["distinct_techniques"] == 1
        assert r["distinct_tactics"] == 1

    def test_non_attack_run_meets_targets_vacuously(self, cov_log):
        cov_log._entries.append(
            _finding("harassing emails from suspect account", call_id=3))
        r = self._run()
        assert r["finding_mapping"]["attack_findings"] == 0
        assert r["targets"]["meets_mapping"] is True
        assert r["targets"]["meets_breadth"] is True


class TestPreReportBreadthAndSpam:
    @pytest.fixture
    def configured_log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST-TTP", str(tmp_path / "trace.json"))
        # The coverage floor is a real gate; these tests exercise the TTP
        # checks, so give them a case whose floor is met.
        import json
        (tmp_path / ".atlas").mkdir(exist_ok=True)
        (tmp_path / ".atlas" / "evidence_inventory.json").write_text(
            json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
        return l

    def _happy_path(self, l):
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        l.record_reason_call("reason_plan", True, "plan", {})
        l.record_reason_call("reason_hypothesize", True, "hyp", {})
        l.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        l.record_reason_call("reason_synthesize", True, "ok", {})

    def _check(self, l):
        from tools.reasoning import reason_pre_report_check
        with patch("core.execution_log.log", l):
            return reason_pre_report_check()

    def test_breadth_warning_fires_but_does_not_block(self, configured_log):
        self._happy_path(configured_log)
        for i in range(5):
            configured_log.record_finding(
                f"ransomware artifact {i} on host (T1486)", "CONFIRMED",
                "ez.mftecmd")
        r = self._check(configured_log)
        assert r["ready_to_report"] is True
        assert any("distinct technique" in w for w in r["warnings"])

    def test_copy_paste_tid_warning(self, configured_log):
        self._happy_path(configured_log)
        for i in range(4):
            configured_log.record_finding(
                f"lateral movement artifact {i} (T1021.002)", "CONFIRMED",
                "ez.mftecmd")
        r = self._check(configured_log)
        assert any("T1021.002" in w and "copy-past" in w.lower()
                   for w in r["warnings"])

    def test_all_unsupported_relevance_warns_but_does_not_block(
            self, configured_log):
        """Findings whose only technique stamps are `unsupported` no longer
        block the report — they warn.

        This assertion used to be the opposite (the test was named
        ...relevance_blocks). The block was dropped deliberately: a
        validated_techniques stamp is immutable once recorded, so
        a single bad stamp early in a run could hold the report gate shut for
        the rest of it with no way back — the same unbounded-deadlock shape the
        productive-stall and budget-wrapup valves exist to prevent. The
        counterpart is test_unsupported_mitre_stamps_do_not_anti_spam_block in
        tests/tools/test_reasoning.py.

        What must NOT be lost is the signal, so this pins that the warning still
        names the affected findings. A silent pass would be the real regression,
        not the missing block.
        """
        self._happy_path(configured_log)
        for i, cid in enumerate((31, 32, 33)):
            configured_log._entries.append(_finding(
                f"backdoor beacon artifact {i}", call_id=cid,
                validated=[{"technique_id": "T1059", "name": "x",
                            "tactic": "Execution",
                            "relevance": "unsupported"}]))
        r = self._check(configured_log)
        assert r["ready_to_report"] is True
        assert not any("unsupported" in i for i in r["blocking_issues"])
        # The downgraded signal: an unsupported stamp does not count as carried,
        # so these findings are reported as carrying no technique, by call_id.
        carried = [w for w in r["warnings"] if "carry no MITRE technique" in w]
        assert carried, r["warnings"]
        assert all(f"#{cid}" in carried[0] for cid in (31, 32, 33))

    def test_supported_relevance_does_not_block(self, configured_log):
        self._happy_path(configured_log)
        for i, cid in enumerate((31, 32, 33)):
            configured_log._entries.append(_finding(
                f"backdoor beacon artifact {i}", call_id=cid,
                validated=[{"technique_id": "T1071", "name": "x",
                            "tactic": "Command and Control"}]))
        r = self._check(configured_log)
        assert not any("unsupported" in i for i in r["blocking_issues"])


class TestGateRelevanceAnnotation:
    def _ctx(self, description, techniques):
        return SimpleNamespace(description=description, confidence="CONFIRMED",
                               mitre_techniques=techniques,
                               validated_techniques=[])

    def _check(self, ctx, candidates):
        from tools._gates import mitre_technique_validation as gate
        with patch("tools.correlate.mitre_map",
                   return_value={"candidates": [
                       {"technique_id": t} for t in candidates]}), \
             patch("tools.correlate.mitre_validate",
                   return_value={"exists": True, "name": "n", "tactic": "t"}):
            return gate.check(ctx)

    def test_candidate_supported_technique_unannotated(self):
        ctx = self._ctx("PsExec service installed for lateral movement",
                        ["T1021.002"])
        assert self._check(ctx, ["T1021.002", "T1570"]) is None
        assert "relevance" not in ctx.validated_techniques[0]

    def test_parent_match_counts_as_supported(self):
        ctx = self._ctx("remote services abuse", ["T1021.002"])
        self._check(ctx, ["T1021"])
        assert "relevance" not in ctx.validated_techniques[0]

    def test_irrelevant_technique_annotated_not_refused(self):
        ctx = self._ctx("harassing emails sent to the victim", ["T1486"])
        assert self._check(ctx, ["T1566"]) is None  # no refusal
        assert ctx.validated_techniques[0]["relevance"] == "unsupported"

    def test_tid_in_description_is_supported(self):
        ctx = self._ctx("encryption event mapped to T1486 by analyst",
                        ["T1486"])
        self._check(ctx, ["T1566"])
        assert "relevance" not in ctx.validated_techniques[0]

    def test_fail_open_when_mitre_map_broken(self):
        from tools._gates import mitre_technique_validation as gate
        ctx = self._ctx("backdoor beacon", ["T1071"])
        with patch("tools.correlate.mitre_map",
                   side_effect=RuntimeError("table missing")), \
             patch("tools.correlate.mitre_validate",
                   return_value={"exists": True, "name": "n", "tactic": "t"}):
            assert gate.check(ctx) is None
        assert "relevance" not in ctx.validated_techniques[0]

    def test_unknown_id_still_refused(self):
        from tools._gates import mitre_technique_validation as gate
        ctx = self._ctx("backdoor beacon", ["T9999"])
        with patch("tools.correlate.mitre_map",
                   return_value={"candidates": []}), \
             patch("tools.correlate.mitre_validate",
                   return_value={"exists": False}):
            r = gate.check(ctx)
        assert r is not None and r["success"] is False
        assert "T9999" in r["error"]
