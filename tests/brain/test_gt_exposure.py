"""Tests for core/brain/gt_exposure.py — seen-vs-reported audit."""
import json

from core.brain import gt_exposure
from core.brain.answer_key import REDACTION


def _tool_call(cid, stdout, tool="strings_strings_grep"):
    return {"type": "tool_call", "call_id": cid, "mcp_tool": tool,
            "cmd": "grep …", "stdout": stdout, "stderr": ""}


def _finding(cid, desc, conf="LIKELY"):
    return {"type": "finding", "call_id": cid, "description": desc,
            "confidence": conf}


GT = {
    "case_id": "EXPO-01",
    "expected_findings": [
        {"id": "G1", "description": "Beacon to 10.11.11.128 from PC01",
         "confidence_min": "LIKELY"},
        {"id": "G2", "description": "Dropper C:\\Users\\Public\\svc.exe",
         "confidence_min": "LIKELY"},
        {"id": "G3", "description": "Attacker moved laterally with intent",
         "confidence_min": "SUSPECTED"},
        {"id": "G4", "description": "Exfil staged to mega.io account "
                                    "leak.hoarder@mega.io",
         "confidence_min": "LIKELY"},
    ],
}


class TestAuditClassification:
    def test_four_way_split(self):
        entries = [
            # G1 surfaced AND reported
            _tool_call(1, "TCP 10.11.11.128:443 ESTABLISHED"),
            # G2 surfaced only (tool saw the path, never became a finding)
            _tool_call(2, r"amcache entry c:\users\public\svc.exe run count 3"),
            _finding(3, "Repeated callbacks to 10.11.11.128 observed"),
        ]
        result = gt_exposure.audit(GT, entries)
        by_id = {i["id"]: i for i in result["items"]}
        assert by_id["G1"]["classification"] == "reported"
        assert by_id["G2"]["classification"] == "surfaced-not-reported"
        assert by_id["G2"]["first_seen_call_id"] == 2
        # G3 is prose-only: no discriminative entity to probe
        assert by_id["G3"]["classification"] == "unassessable"
        # G4's email never appeared anywhere
        assert by_id["G4"]["classification"] == "never-surfaced"
        assert result["summary"]["reported"] == 1

    def test_first_seen_is_earliest_call(self):
        entries = [
            _tool_call(5, "nothing here"),
            _tool_call(7, "svc.exe spotted at c:/users/public/svc.exe"),
            _tool_call(9, r"C:\Users\Public\svc.exe again"),
        ]
        result = gt_exposure.audit(GT, entries)
        by_id = {i["id"]: i for i in result["items"]}
        assert by_id["G2"]["first_seen_call_id"] == 7

    def test_secret_items_redacted(self):
        gt = {"case_id": "CTF", "flags": ["flag{sup3r-s3cret-value}"]}
        entries = [
            _tool_call(1, "console dump contains flag{sup3r-s3cret-value}"),
        ]
        result = gt_exposure.audit(gt, entries)
        secret_items = [i for i in result["items"]
                        if i["kind"] == "answer_key_secret"]
        assert secret_items
        assert secret_items[0]["classification"] == "surfaced-not-reported"
        assert secret_items[0]["description"] == REDACTION
        assert "s3cret" not in json.dumps(result)

    def test_secret_reported_when_in_finding(self):
        gt = {"case_id": "CTF", "flags": ["flag{sup3r-s3cret-value}"]}
        entries = [
            _tool_call(1, "console dump contains flag{sup3r-s3cret-value}"),
            _finding(2, "Recovered flag{sup3r-s3cret-value} from console",
                     "CONFIRMED"),
        ]
        result = gt_exposure.audit(gt, entries)
        secret_items = [i for i in result["items"]
                        if i["kind"] == "answer_key_secret"]
        assert secret_items[0]["classification"] == "reported"


class TestAuditCase:
    def test_writes_json_and_survives_missing_gt(self, tmp_path):
        # no ground truth → None, no file
        assert gt_exposure.audit_case(tmp_path, {"entries": [_tool_call(1, "x")]}) is None

        (tmp_path / "ground_truth.json").write_text(json.dumps(GT))
        trace = {"entries": [
            _tool_call(1, "TCP 10.11.11.128:443"),
            _finding(2, "Callbacks to 10.11.11.128"),
        ]}
        result = gt_exposure.audit_case(tmp_path, trace)
        assert result is not None
        out = tmp_path / "analysis" / "gt_exposure.json"
        assert out.is_file()
        data = json.loads(out.read_text())
        assert data["case_id"] == "EXPO-01"
        assert {i["id"] for i in data["items"]} >= {"G1", "G2", "G3", "G4"}

    def test_never_raises_on_malformed_gt(self, tmp_path):
        (tmp_path / "ground_truth.json").write_text("{not json")
        assert gt_exposure.audit_case(tmp_path, {"entries": [_tool_call(1, "x")]}) is None


class TestSurfaceCorpus:
    def test_preamble_narration_counts_as_surface(self):
        """Live-monitoring investigations open with a system-written alert
        bundle narration — that IS the evidence surface (DEMO-LIVE's
        detections arrive that way)."""
        entries = [
            {"type": "investigation_narration", "call_id": 1,
             "content": "Investigation opened on 1 alert(s): beacon to "
                        "10.11.11.128 detected"},
            _finding(3, "Beacon to 10.11.11.128 confirmed from PC01"),
        ]
        result = gt_exposure.audit(GT, entries)
        g1 = {i["id"]: i for i in result["items"]}["G1"]
        assert g1["classification"] == "reported"
        assert g1["first_seen_call_id"] == 1
        assert g1["first_seen_tool"] == "(alert-preamble)"

    def test_command_text_is_not_evidence(self):
        """Typing the answer into a command argument must NOT count as
        surfacing — otherwise a run that already knows an answer parrots it
        by naming the entity in a grep. Only tool OUTPUT counts."""
        entries = [
            {"type": "tool_call", "call_id": 1, "mcp_tool": "strings_grep",
             "cmd": "grep -i 10.11.11.128 /mnt/img",   # entity only in cmd
             "stdout_excerpt": "no matches found", "stderr": ""},
            _finding(2, "Beacon to 10.11.11.128 from PC01"),
        ]
        result = gt_exposure.audit(GT, entries)
        g1 = {i["id"]: i for i in result["items"]}["G1"]
        assert g1["classification"] == "reported"
        assert g1["first_seen_call_id"] is None  # parroted — cmd is not output
        summary = gt_exposure.integrity_summary(result)
        assert "G1" in summary["parroted"]

    def test_stdout_excerpt_counts_as_evidence(self):
        entries = [
            {"type": "tool_call", "call_id": 1, "mcp_tool": "strings_grep",
             "cmd": "grep -i beacon /mnt/img",
             "stdout_excerpt": "TCP 10.11.11.128:443 ESTABLISHED", "stderr": ""},
            _finding(2, "Beacon to 10.11.11.128 from PC01"),
        ]
        summary = gt_exposure.integrity_summary(gt_exposure.audit(GT, entries))
        assert summary["parroted"] == []

    def test_mid_run_narration_never_counts(self):
        """Narration after agent activity is the agent's own text — counting
        it would mask parroting."""
        entries = [
            _tool_call(1, "nothing relevant here"),
            {"type": "investigation_narration", "call_id": 2,
             "content": "I suspect a beacon to 10.11.11.128"},
            _finding(3, "Beacon to 10.11.11.128 confirmed from PC01"),
        ]
        result = gt_exposure.audit(GT, entries)
        g1 = {i["id"]: i for i in result["items"]}["G1"]
        assert g1["classification"] == "reported"
        assert g1["first_seen_call_id"] is None  # parroted


class TestIntegritySummary:
    def test_parroted_derivation(self):
        entries = [
            _tool_call(1, "TCP 10.11.11.128:443 ESTABLISHED"),
            _finding(2, "Beacon to 10.11.11.128 from PC01"),           # G1 ok
            _finding(3, "Dropper C:\\Users\\Public\\svc.exe planted"),  # G2 parroted
        ]
        summary = gt_exposure.integrity_summary(gt_exposure.audit(GT, entries))
        assert summary["scorable"] is True
        assert summary["parroted"] == ["G2"]

    def test_unassessable_reported_item_not_parroted(self):
        """G3 is prose-only (no probes) — reported without surface evidence
        must not count as parroting; there was nothing to probe for."""
        entries = [
            _finding(1, "Attacker moved laterally with intent to exfil"),
        ]
        summary = gt_exposure.integrity_summary(gt_exposure.audit(GT, entries))
        assert "G3" not in summary["parroted"]

    def test_unscorable_gt(self):
        summary = gt_exposure.integrity_summary(gt_exposure.audit(
            {"case_id": "CTF", "flag": "d41d8cd98f00b204e9800998ecf8427e"},
            [_finding(1, "some finding")]))
        assert summary == {"scorable": False}

    def test_none_result_passthrough(self):
        assert gt_exposure.integrity_summary(None) is None

    def test_answer_key_hits(self):
        gt = dict(GT, secrets=["s3cretflagvalue"])
        entries = [_tool_call(1, "log line with s3cretflagvalue inside")]
        summary = gt_exposure.integrity_summary(gt_exposure.audit(gt, entries))
        assert summary["answer_key_hits"] == ["secret#1"]


class TestAuditRunDir:
    def test_split_gt_and_trace_sources(self, tmp_path):
        gt_dir = tmp_path / "realcase"
        gt_dir.mkdir()
        (gt_dir / "ground_truth.json").write_text(json.dumps(GT))
        run_dir = tmp_path / "bench" / "run-1"
        (run_dir / "analysis").mkdir(parents=True)
        (run_dir / "analysis" / "X_trace.json").write_text(json.dumps(
            {"entries": [_tool_call(1, "TCP 10.11.11.128:443"),
                         _finding(2, "Beacon to 10.11.11.128 from PC01")]}))
        result = gt_exposure.audit_run_dir(gt_dir, run_dir)
        assert result is not None
        assert (run_dir / "analysis" / "gt_exposure.json").is_file()
        by_id = {i["id"]: i for i in result["items"]}
        assert by_id["G1"]["classification"] == "reported"

    def test_none_without_gt_or_trace(self, tmp_path):
        empty = tmp_path / "empty"
        (empty / "analysis").mkdir(parents=True)
        assert gt_exposure.audit_run_dir(empty, empty) is None
        (empty / "ground_truth.json").write_text(json.dumps(GT))
        assert gt_exposure.audit_run_dir(empty, tmp_path / "norun") is None


class TestBundledClassification:
    def test_fact_inside_a_credited_finding_is_reported_bundled(self):
        gt = {"case_id": "EXPO-02", "expected_findings": [
            {"id": "G1", "description": "Beacon to 10.11.11.128 from PC01",
             "confidence_min": "LIKELY"},
            {"id": "G2", "description": "Dropper C:\\Users\\Public\\svc.exe",
             "confidence_min": "LIKELY"},
        ]}
        entries = [
            _tool_call(1, r"amcache entry c:\users\public\svc.exe run count 3"),
            _finding(2, "Repeated callbacks to 10.11.11.128 observed from PC01. "
                        r"The dropper C:\Users\Public\svc.exe started them."),
        ]
        result = gt_exposure.audit(gt, entries)
        by_id = {i["id"]: i for i in result["items"]}
        assert by_id["G1"]["classification"] == "reported"
        # on record in the same finding: not an attention gap, a grading one
        assert by_id["G2"]["classification"] == "reported-bundled"
        assert result["summary"] == {"reported": 1, "reported-bundled": 1}
