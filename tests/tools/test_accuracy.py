"""Tests for tools/accuracy.py — ground-truth comparison."""
import json
import os
import pytest
from unittest.mock import patch
from core.execution_log import ExecutionLog
from tests._edition import DEVTOOLS_SHIPPED, NO_DEV_DATA


def _gt_file(tmp_path, items, case_id="TEST", negatives=None):
    """Write a ground-truth JSON file and return its path."""
    p = tmp_path / "ground_truth.json"
    p.write_text(json.dumps({
        "case_id": case_id,
        "expected_findings": items,
        "negative_assertions": negatives or [],
    }))
    return str(p)


def _configure_log(tmp_path, findings):
    """Configure a fresh ExecutionLog with a dair_call seed and given findings."""
    l = ExecutionLog()
    l.configure("TEST", str(tmp_path / "trace.json"))
    l.record_dair_call("Triage", "", False, "", "", "stay", "")
    for desc, conf in findings:
        l.record_finding(desc, conf, "test")
    return l


class TestAccuracyCompareBasics:
    def test_perfect_match(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(tmp_path, [
            {"id": "F1", "description": "toolx.exe at C:\\Windows\\Temp",
             "confidence_min": "CONFIRMED", "category": "implant"},
        ])
        l = _configure_log(tmp_path, [
            ("toolx.exe at C:\\Windows\\Temp confirmed", "CONFIRMED"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["success"] is True
        assert r["summary"]["true_positive_count"] == 1
        assert r["summary"]["false_positive_count"] == 0
        assert r["summary"]["false_negative_count"] == 0
        assert r["summary"]["precision"] == 1.0
        assert r["summary"]["recall"] == 1.0
        assert r["summary"]["f1"] == 1.0

    def test_ctf_flag_answer_key_is_unscorable_not_zero(self, tmp_path):
        """A CTF grader key (flag + per-question MD5s) has no expected_findings.
        It must return unscorable, NOT precision=0 with all findings as FPs —
        that false 0% reads as a NEEDS WORK verdict."""
        from tools.accuracy import accuracy_compare
        p = tmp_path / "ground_truth.json"
        p.write_text(json.dumps({
            "flag": "flag{example-f1ag-n0t-r3al-0c0de}",
            "1": "0c0de5a3b1c2d4e6f708192a3b4c5d6e",
            "2": "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
        }))
        l = _configure_log(tmp_path, [
            ("Phishing email from alice@example.com", "LIKELY"),
            ("Miner config retrieved from 10.0.0.5", "LIKELY"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(str(p))
        assert r["success"] is True
        assert r["unscorable"] is True
        assert r["summary"] is None
        assert "expected_findings" in r["reason"]

    def test_wellformed_gt_with_empty_expected_is_still_scored(self, tmp_path):
        """A proper Atlas GT with an empty expected_findings list (but the
        schema keys present) is NOT unscorable — it still scores negative
        coverage. Only schema-absent CTF keys are unscorable."""
        from tools.accuracy import accuracy_compare
        gt = _gt_file(tmp_path, [], negatives=[])
        l = _configure_log(tmp_path, [])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert not r.get("unscorable")
        assert r["summary"] is not None

    def test_missing_finding_counts_false_negative(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(tmp_path, [
            {"id": "F1", "description": "toolx.exe at C:\\Windows\\Temp",
             "confidence_min": "CONFIRMED"},
            {"id": "F2", "description": "driverx.sys kernel rootkit",
             "confidence_min": "CONFIRMED"},
        ])
        l = _configure_log(tmp_path, [
            ("toolx.exe at C:\\Windows\\Temp", "CONFIRMED"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["summary"]["false_negative_count"] == 1
        assert any(fn["id"] == "F2" for fn in r["false_negatives"])

    def test_extra_finding_counts_false_positive(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(tmp_path, [
            {"id": "F1", "description": "toolx.exe at Windows Temp",
             "confidence_min": "CONFIRMED"},
        ])
        l = _configure_log(tmp_path, [
            ("toolx.exe at Windows Temp", "CONFIRMED"),
            ("Unrelated finding nobody asked for", "LIKELY"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["summary"]["false_positive_count"] == 1
        assert any("Unrelated" in fp["description"] for fp in r["false_positives"])

    def test_confidence_downgrade_recorded(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(tmp_path, [
            {"id": "F1", "description": "toolx.exe at Windows Temp",
             "confidence_min": "CONFIRMED"},
        ])
        l = _configure_log(tmp_path, [
            ("toolx.exe at Windows Temp", "SUSPECTED"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        # Match is found (TP) but at lower tier — recorded as downgrade.
        assert r["summary"]["true_positive_count"] == 1
        assert len(r["confidence_downgrades"]) == 1
        assert r["confidence_downgrades"][0]["expected_tier"] == "CONFIRMED"
        assert r["confidence_downgrades"][0]["actual_tier"] == "SUSPECTED"

    def test_higher_confidence_does_not_count_as_downgrade(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(tmp_path, [
            {"id": "F1", "description": "toolx.exe at Windows Temp",
             "confidence_min": "LIKELY"},
        ])
        l = _configure_log(tmp_path, [
            ("toolx.exe at Windows Temp", "CONFIRMED"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["confidence_downgrades"] == []

    def test_missing_ground_truth_file(self):
        from tools.accuracy import accuracy_compare
        r = accuracy_compare("/nonexistent/gt.json")
        assert r["success"] is False
        assert "not found" in r["error"]

    def test_empty_trace_all_false_negatives(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(tmp_path, [
            {"id": "F1", "description": "toolx.exe", "confidence_min": "CONFIRMED"},
            {"id": "F2", "description": "driverx rootkit", "confidence_min": "CONFIRMED"},
        ])
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["summary"]["false_negative_count"] == 2
        assert r["summary"]["recall"] == 0.0


class TestAccuracyExportReport:
    def test_writes_markdown(self, tmp_path):
        from tools.accuracy import accuracy_export_report
        gt = _gt_file(tmp_path, [
            {"id": "F1", "description": "toolx.exe at Windows Temp",
             "confidence_min": "CONFIRMED"},
        ], case_id="WRITE-001")
        l = _configure_log(tmp_path, [
            ("toolx.exe at Windows Temp", "CONFIRMED"),
        ])
        out_dir = tmp_path / "analysis"
        out_dir.mkdir()
        out_path = str(out_dir / "accuracy.md")
        with patch("core.execution_log.log", l):
            r = accuracy_export_report(gt, out_path)
        assert r["success"] is True
        content = (out_dir / "accuracy.md").read_text()
        assert "Accuracy Report" in content
        assert "WRITE-001" in content
        assert "True positives: **1**" in content

    def test_refuses_output_inside_evidence(self, tmp_path):
        from tools.accuracy import accuracy_export_report
        gt = _gt_file(tmp_path, [])
        with pytest.raises(ValueError):
            accuracy_export_report(gt, "/mnt/host01/accuracy.md")


class TestGroundTruthSchema:
    """Any ground_truth.json present under ~/cases/* is well-formed.

    Case-agnostic: globs whatever ground-truth files exist and validates the
    schema; skips when none are present so the suite has no hard coupling to a
    particular dataset being installed."""

    def test_present_ground_truth_files_validate(self):
        import os, glob
        paths = glob.glob(os.path.expanduser("~/cases/*/ground_truth.json"))
        if not paths:
            pytest.skip("no ground_truth.json present under ~/cases/")
        for path in paths:
            with open(path) as f:
                gt = json.load(f)
            assert gt.get("case_id")
            assert isinstance(gt.get("expected_findings"), list)
            for item in gt["expected_findings"]:
                assert "id" in item
                assert "description" in item
                assert item.get("confidence_min") in ("CONFIRMED", "LIKELY", "SUSPECTED")


class TestAsymmetricMatching:
    """Long evidence-rich findings must match short ground-truth lines. A
    symmetric Jaccard score dilutes every match below threshold because the
    finding's extra tokens inflate the union, so a graded run scores f1 0.0
    even when every reference line is contained verbatim."""

    CFREDS_GT = os.path.join(
        os.path.dirname(__file__), "..", "..", "benchmarks", "cfreds-leak",
        "ground_truth.json")

    # A long finding that contains a ground-truth line verbatim yet scores
    # below 0.1 under symmetric Jaccard against GT13.
    RM2_FINDING = (
        "RM#2 (unauthorized USB, FAT32, serial 4C530012550531106501, volume "
        "label 'IAMAN') shows anti-forensics: deletion + decoy renaming — "
        "confidential files renamed to innocuous decoy names such as "
        "winter_storm.amr, winter_whether_advisory.zip, my_favorite_cars.db "
        "and new_years_day.jpg, then deleted from the FAT directory; entries "
        "remain recoverable from unallocated clusters."
    )

    def test_verbatim_embedded_gt_line_scores_near_one(self):
        """A finding that contains the GT line verbatim, buried in a long
        paragraph, must score ~1.0 — full containment of the reference."""
        from tools.accuracy import _match_score
        gt_line = ("RM#2 anti-forensics: confidential files renamed to "
                   "innocuous names and deleted from FAT, recoverable")
        finding = (
            "During analysis of the second removable device the following was "
            "established beyond doubt. " + gt_line + " Evidence: FAT32 "
            "directory entries for design, PRICIN~1, progress, proposal and "
            "TECHNI~1 all carry the 0xE5 deletion marker, serial "
            "4C530012550531106501 ties the device to USBSTOR, and carving "
            "restored every file intact."
        )
        assert _match_score(gt_line, finding) >= 0.95

    @pytest.mark.skipif(not DEVTOOLS_SHIPPED, reason=NO_DEV_DATA)
    def test_long_rm2_finding_matches_gt13_above_threshold(self):
        """A rich RM#2 finding matches GT13 above the threshold."""
        from tools.accuracy import _match_score
        with open(self.CFREDS_GT) as f:
            gt13 = [i for i in json.load(f)["expected_findings"]
                    if i["id"] == "GT13"][0]
        assert _match_score(gt13["description"], self.RM2_FINDING) > 0.30

    @pytest.mark.skipif(not DEVTOOLS_SHIPPED, reason=NO_DEV_DATA)
    def test_cfreds_gt13_true_positive_end_to_end(self, tmp_path):
        """accuracy_compare with the shipped cfreds-leak ground truth must
        credit the RM#2 finding as a true positive, not a false positive."""
        from tools.accuracy import accuracy_compare
        l = _configure_log(tmp_path, [(self.RM2_FINDING, "LIKELY")])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(self.CFREDS_GT)
        assert r["success"] is True
        assert r["summary"]["true_positive_count"] == 1
        assert r["summary"]["false_positive_count"] == 0
        matched_ids = {tp["ground_truth_id"] for tp in r["true_positives"]}
        assert matched_ids & {"GT12", "GT13", "GT25"}

    def test_high_signal_serial_boosts_score(self):
        """A shared device serial is near-unique — it must lift an otherwise
        thin overlap above the default threshold."""
        from tools.accuracy import _match_score
        gt = ("USB device RM#2 unauthorized SanDisk Cruzer Fit serial "
              "4C530012550531106501 attached")
        finding = ("USBSTOR registry entries confirm device serial "
                   "4C530012550531106501 was connected to the PC")
        assert _match_score(gt, finding) > 0.30

    def test_high_signal_email_boosts_score(self):
        from tools.accuracy import _match_score
        gt = "Spy Conspirator email address is spy.conspirator@nist.gov"
        finding = ("Outlook OST contains an 11-message thread between "
                   "iaman.informant@nist.gov and spy.conspirator@nist.gov "
                   "discussing payment for leaked technology documents")
        assert _match_score(gt, finding) > 0.30

    def test_unrelated_long_finding_stays_below_threshold(self):
        """Containment must not turn every long finding into a match."""
        from tools.accuracy import _match_score
        gt = ("Sticky Notes content recovered from informant profile")
        finding = (
            "Timestomp evidence detected: 200 MFT records show "
            "$STANDARD_INFORMATION timestamps earlier than $FILE_NAME, "
            "concentrated under Program Files and Windows directories, "
            "consistent with installer activity rather than manual tampering."
        )
        assert _match_score(gt, finding) <= 0.30

    def test_single_generic_shared_token_does_not_match(self):
        from tools.accuracy import _match_score
        assert _match_score(
            "Recycle Bin was emptied as anti-forensics",
            "Recycle activity unrelated to the incident window",
        ) == 0.0


class TestNegativeAssertionScoring:
    """Negative-assertion scoring: negative_assertions in ground_truth are scored against
    UNCONFIRMED findings in the trace."""

    def test_unaddressed_negative_assertion(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(
            tmp_path,
            [{"id": "F1", "description": "toolx.exe", "confidence_min": "CONFIRMED"}],
            negatives=["No persistence via Run keys"],
        )
        l = _configure_log(tmp_path, [("toolx.exe", "CONFIRMED")])
        # Findings recorded but the negative assertion is never addressed.
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["summary"]["negative_assertion_total"] == 1
        assert r["summary"]["negative_assertion_addressed"] == 0
        assert r["summary"]["negative_coverage"] == 0.0
        assert r["negative_assertions"][0]["addressed"] is False

    def test_addressed_negative_assertion(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(
            tmp_path,
            [],
            negatives=["No persistence via Run keys — verified via RECmd"],
        )
        l = _configure_log(tmp_path, [
            ("No persistence via Run keys — verified via RECmd", "UNCONFIRMED"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["summary"]["negative_assertion_addressed"] == 1
        assert r["summary"]["negative_coverage"] == 1.0
        assert r["negative_assertions"][0]["addressed"] is True

    def test_no_negative_assertions_means_full_coverage(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(tmp_path, [], negatives=[])
        l = _configure_log(tmp_path, [])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["summary"]["negative_coverage"] == 1.0
        assert r["negative_assertions"] == []

    def test_likely_finding_does_not_count_as_negative_assertion(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(
            tmp_path,
            [],
            negatives=["No persistence via Run keys"],
        )
        # LIKELY POSITIVE finding that matches text — must NOT satisfy the
        # negative assertion: it claims presence, not absence.
        l = _configure_log(tmp_path, [
            ("Persistence via Run keys exists", "LIKELY"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["negative_assertions"][0]["addressed"] is False

    def test_trailing_caveat_does_not_make_finding_absence_shaped(self, tmp_path):
        """A tiered multi-claim finding ending in an unrelated caveat ('does
        not by itself prove…') must NOT satisfy a negative assertion it only
        shares generic tokens with — the negation must be in the matching
        sentence."""
        from tools.accuracy import accuracy_compare
        gt = _gt_file(
            tmp_path, [],
            negatives=["No BadUSB keystroke-injection device present"],
        )
        l = _configure_log(tmp_path, [
            ("RM#3 CD-R was mounted at drive D: on the PC, evidenced by LNK "
             "shortcuts. Carving recovered OOXML ZIP structures, indicating "
             "Office-document containers are present on the disc; this does "
             "not by itself prove the device payloads are unencrypted.",
             "LIKELY"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["negative_assertions"][0]["addressed"] is False

    def test_absence_shaped_likely_finding_counts(self, tmp_path):
        """A verified absence recorded above UNCONFIRMED still satisfies the
        assertion — tier expresses confidence in the absence, not presence."""
        from tools.accuracy import accuracy_compare
        gt = _gt_file(
            tmp_path,
            [],
            negatives=["No persistence via Run keys"],
        )
        l = _configure_log(tmp_path, [
            ("No persistence via Run keys — verified via RECmd sweep",
             "LIKELY"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["negative_assertions"][0]["addressed"] is True
        assert r["negative_assertions"][0]["matched_confidence"] == "LIKELY"


class TestEntityMatching:
    """v2 matcher: canonical entities rescue matches token overlap misses."""

    def test_ip_with_port_matches_bare_ip(self):
        from tools.accuracy import _match_detail
        gt = "C2 beacon to 10.0.1.128 over HTTPS"
        finding = ("Sustained TLS sessions from PC01 to 10.0.1.128:443 "
                   "with JA3 matching Cobalt Strike")
        score, quality = _match_detail(gt, finding)
        assert score > 0.30
        assert quality == "entity"

    def test_timestamp_format_difference_matches(self):
        from tools.accuracy import _match_detail
        gt = "Initial access 2031-02-04T12:15:00Z via phishing attachment"
        finding = ("Outlook shows the malicious attachment was opened "
                   "2031-02-04 12:15:33, spawning winword.exe")
        score, quality = _match_detail(gt, finding)
        assert score > 0.30
        assert quality == "entity"

    def test_path_separator_and_case_difference_matches(self):
        from tools.accuracy import _match_detail
        gt = r"Dropper at C:\Users\Public\svc.exe"
        finding = "Amcache places c:/users/public/svc.exe first run 09:00"
        score, quality = _match_detail(gt, finding)
        assert score > 0.30
        assert quality == "entity"

    def test_prose_only_match_flagged_token_quality(self):
        from tools.accuracy import _match_detail
        score, quality = _match_detail(
            "Sticky Notes content recovered from informant profile",
            "Recovered Sticky Notes content from the informant user profile",
        )
        assert score > 0.30
        assert quality == "token"

    def test_true_positive_carries_match_quality(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(tmp_path, [
            {"id": "F1", "description": "Beacon to 10.0.1.128",
             "confidence_min": "LIKELY"},
        ])
        l = _configure_log(tmp_path, [
            ("Repeated callbacks to 10.0.1.128:443 observed", "LIKELY"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["summary"]["true_positive_count"] == 1
        assert r["true_positives"][0]["match_quality"] == "entity"
        assert r["summary"]["matcher_version"] == 2


class TestKeyFormatDeclared:
    def test_declared_key_format_is_unscorable_with_specific_reason(self, tmp_path):
        from tools.accuracy import accuracy_compare
        p = tmp_path / "ground_truth.json"
        p.write_text(json.dumps({
            "case_id": "CTF-01",
            "key_format": "md5-per-question",
            "1": "not-even-a-hash-shape",
        }))
        l = _configure_log(tmp_path, [("Some finding", "LIKELY")])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(str(p))
        assert r["unscorable"] is True
        assert "key_format" in r["reason"]


class TestBundledFacts:
    """The finding-level match consumes a finding per key item; facts a
    finding states in its other sentences are reported separately as
    bundled, without touching precision, recall or f1."""

    GT = [
        {"id": "K1", "description": "Registered owner is Jordan Vale",
         "confidence_min": "SUSPECTED"},
        {"id": "K2", "description": "Computer account name WS-77QX2P",
         "confidence_min": "SUSPECTED"},
    ]

    def test_composite_finding_second_fact_is_bundled_not_credited(self):
        from tools.accuracy import compare_findings
        findings = [{"description": (
            "System baseline: registered owner is Jordan Vale. "
            "Computer name: WS-77QX2P. Product type: workstation."),
            "confidence": "LIKELY", "call_id": 7}]
        r = compare_findings({"expected_findings": self.GT}, findings)
        s = r["summary"]
        # primary metrics keep their 1:1 meaning
        assert (s["true_positive_count"], s["false_negative_count"]) == (1, 1)
        assert s["precision"] == 1.0 and s["recall"] == 0.5
        # the second fact is on record, in the same finding
        assert [b["ground_truth_id"] for b in r["bundled"]] == ["K2"]
        assert r["bundled"][0]["trace_call_id"] == 7
        assert "WS-77QX2P" in r["bundled"][0]["sentence"]
        assert s["bundled_count"] == 1 and s["fact_recall"] == 1.0

    def test_one_fact_per_finding_has_nothing_to_bundle(self):
        from tools.accuracy import compare_findings
        findings = [
            {"description": "Registered owner is Jordan Vale", "confidence": "LIKELY"},
            {"description": "Computer name WS-77QX2P", "confidence": "LIKELY"},
            {"description": "Unrelated: proxy cache purged nightly", "confidence": "LIKELY"},
        ]
        r = compare_findings({"expected_findings": self.GT}, findings)
        s = r["summary"]
        assert s["true_positive_count"] == 2 and s["false_positive_count"] == 1
        assert r["bundled"] == [] and s["fact_recall"] == s["recall"]

    def test_negative_sentence_does_not_bundle_a_positive_item(self):
        from tools.accuracy import compare_findings
        gt = [{"id": "K1", "description": "Registered owner is Jordan Vale"},
              {"id": "K2", "description": "Hidden payload recovered from cover.jpg"}]
        findings = [{"description": (
            "Registered owner is Jordan Vale. "
            "No hidden payload was recovered from cover.jpg with any candidate key."),
            "confidence": "LIKELY"}]
        r = compare_findings({"expected_findings": gt}, findings)
        assert r["summary"]["true_positive_count"] == 1
        assert r["bundled"] == []

    def test_sentence_about_another_artifact_does_not_bundle(self):
        from tools.accuracy import compare_findings
        gt = [{"id": "K1", "description": "Registered owner is Jordan Vale"},
              {"id": "K2", "description": "The primary user's webmail address is "
                                           "vale.j@example.net"}]
        findings = [{"description": (
            "Registered owner is Jordan Vale. "
            "The intercepted third party's webmail address is other.person@example.org, "
            "the primary user's address does not appear in the capture."),
            "confidence": "LIKELY"}]
        r = compare_findings({"expected_findings": gt}, findings)
        assert r["summary"]["true_positive_count"] == 1
        assert r["bundled"] == []

    def test_prose_only_sentence_must_state_most_of_the_item(self):
        from tools.accuracy import compare_findings
        gt = [{"id": "K1", "description": "Registered owner is Jordan Vale"},
              {"id": "K2", "description": "Ten different rhino images are recoverable "
                                           "from the drive"}]
        # two of six content words shared: above the paragraph threshold,
        # under the majority a sentence has to state
        findings = [{"description": (
            "Registered owner is Jordan Vale. "
            "The carved photos are larger rhino images."),
            "confidence": "LIKELY"}]
        r = compare_findings({"expected_findings": gt}, findings)
        from tools.accuracy import _match_score
        assert _match_score(gt[1]["description"], "The carved photos are larger rhino images.") > 0.30
        assert r["bundled"] == []
        # a shared canonical entity needs no majority
        findings[0]["description"] = (
            "Registered owner is Jordan Vale. Serial 4C530012550531106501 seen in USBSTOR.")
        gt[1] = {"id": "K2", "description": "Unauthorized stick serial 4C530012550531106501 attached"}
        r = compare_findings({"expected_findings": gt}, findings)
        assert [b["ground_truth_id"] for b in r["bundled"]] == ["K2"]
        assert r["bundled"][0]["match_quality"] == "entity"

    def test_sentence_is_consumed_once(self):
        from tools.accuracy import compare_findings
        gt = [{"id": "K1", "description": "Registered owner is Jordan Vale"},
              {"id": "K2", "description": "Computer account name WS-77QX2P"},
              {"id": "K3", "description": "Computer account name WS-77QX2P (duplicate item)"}]
        findings = [{"description": "Registered owner is Jordan Vale. Computer name: WS-77QX2P.",
                     "confidence": "LIKELY"}]
        r = compare_findings({"expected_findings": gt}, findings)
        assert len(r["bundled"]) == 1
