"""ATT&CK Navigator + STIX/IOC exports (tools/export_tools.py)."""
import json

import pytest

from tools import export_tools as et


def _finding(desc, confidence="CONFIRMED", validated=None, call_id=1):
    f = {"type": "finding", "call_id": call_id, "description": desc,
         "confidence": confidence}
    if validated:
        f["validated_techniques"] = validated
    return f


CONFIRMED_C2 = _finding(
    "Beacon to 198.51.100.2 over http://evil.example.com/gate.php, dropper "
    "sha256 " + "ab" * 32 + " mailed from mr_evil@hushmail.com",
    validated=[{"technique_id": "T1071.001",
                "name": "Web Protocols", "tactic": "command-and-control"}],
    call_id=41)


class TestNavigator:
    def test_layer_scores_by_tier_and_flags_unvalidated(self):
        findings = [
            CONFIRMED_C2,
            _finding("Persistence via Run key, see T1547.001",
                     confidence="SUSPECTED", call_id=42),
        ]
        layer = et.build_navigator_layer("CASE-1", findings)
        by_tid = {t["techniqueID"]: t for t in layer["techniques"]}
        assert by_tid["T1071.001"]["score"] == 100  # CONFIRMED, validated
        assert "unvalidated" not in by_tid["T1071.001"]["comment"]
        assert by_tid["T1547.001"]["score"] == 50   # SUSPECTED, desc-only
        assert "unvalidated" in by_tid["T1547.001"]["comment"]
        assert by_tid["T1547.001"]["showSubtechniques"] is True

    def test_highest_tier_wins(self):
        findings = [
            _finding("x T1059", confidence="UNCONFIRMED"),
            _finding("y T1059", confidence="CONFIRMED"),
        ]
        layer = et.build_navigator_layer("C", findings)
        assert layer["techniques"][0]["score"] == 100

    def test_write_navigator_refuses_empty(self, tmp_path):
        out = et.write_navigator("C", [_finding("no techniques here")],
                                 str(tmp_path / "analysis"))
        assert out["success"] is False


class TestIocExtraction:
    def test_types_extracted_from_confirmed(self):
        iocs = et.extract_iocs([CONFIRMED_C2])
        types = {i["type"]: i["value"] for i in iocs}
        assert types["ipv4"] == "198.51.100.2"
        assert types["sha256"] == "ab" * 32
        assert types["url"].startswith("http://evil.example.com")
        assert types["email"] == "mr_evil@hushmail.com"
        assert all(i["severity"] == "CONFIRMED" for i in iocs)
        assert all(i["finding_call_id"] == 41 for i in iocs)

    def test_suspected_findings_excluded(self):
        iocs = et.extract_iocs([_finding("beacon to 1.2.3.4",
                                         confidence="SUSPECTED")])
        assert iocs == []

    def test_dedup_across_findings(self):
        iocs = et.extract_iocs([_finding("ip 1.2.3.4"),
                                _finding("again 1.2.3.4")])
        assert len([i for i in iocs if i["type"] == "ipv4"]) == 1

    def test_csv_shape(self):
        csv_text = et.build_ioc_csv(et.extract_iocs([CONFIRMED_C2]))
        assert csv_text.splitlines()[0] == \
            "type,value,severity,context,finding_call_id"
        assert "198.51.100.2" in csv_text


class TestStixBundle:
    def test_relationship_direction_is_indicator_to_attack_pattern(self):
        # The Mulder bug this port fixes: source_ref was the identity.
        bundle = et.build_stix_bundle("C", [CONFIRMED_C2])
        rels = [o for o in bundle["objects"]
                if o["type"] == "relationship"]
        assert rels, "expected indicator->attack-pattern relationships"
        for rel in rels:
            assert rel["relationship_type"] == "indicates"
            assert rel["source_ref"].startswith("indicator--")
            assert rel["target_ref"].startswith("attack-pattern--")

    def test_relationships_grounded_in_same_finding(self):
        # IOC in one finding, technique in another: no cross edge.
        bundle = et.build_stix_bundle("C", [
            _finding("beacon 1.2.3.4"),
            _finding("persistence",
                     validated=[{"technique_id": "T1547",
                                 "name": "Boot Autostart"}]),
        ])
        assert [o for o in bundle["objects"]
                if o["type"] == "indicator"]
        assert [o for o in bundle["objects"]
                if o["type"] == "attack-pattern"]
        assert not [o for o in bundle["objects"]
                    if o["type"] == "relationship"]

    def test_bundle_objects_well_formed(self):
        bundle = et.build_stix_bundle("C", [CONFIRMED_C2])
        assert bundle["type"] == "bundle"
        for obj in bundle["objects"]:
            assert obj.get("id", "bundle").split("--")[0] == obj["type"]
            if obj["type"] != "bundle":
                assert obj["spec_version"] == "2.1"
        aps = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
        assert aps[0]["external_references"][0]["external_id"] == "T1071.001"
        assert aps[0]["name"] == "Web Protocols"


class TestWriters:
    def test_write_iocs_all(self, tmp_path):
        out_dir = tmp_path / "exports"
        r = et.write_iocs("CASE-9", [CONFIRMED_C2], str(out_dir))
        assert r["success"] is True and r["ioc_count"] >= 4
        stix = json.loads((out_dir / "CASE-9.iocs.stix.json").read_text())
        assert stix["type"] == "bundle"
        assert (out_dir / "CASE-9.iocs.csv").read_text().count("\n") >= 4
