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
    "sha256 " + "ab" * 32 + " mailed from mallory@mail.example.net",
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


def _sight(call, host="CORP-WS05", cited=True):
    return {"call": call, "tool": "table_table_grep", "host": host, "cited": cited, "located": True,
            "first": "2031-03-01 08:12:00", "last": "2031-03-09 17:40:00", "rows": 2}


def _case(tmp_path):
    """An invented case: a cited sighted address and domain on one claim, a
    private address only in the finding's text, a legacy unchecked row and a
    presence-refused value."""
    d = tmp_path / "case"
    (d / ".atlas").mkdir(parents=True)
    (d / "CASE.md").write_text("# Case: CASE-9\n\n**Case ID:** CASE-9\n")
    graph = {"nodes": {
        "C0001": {"id": "C0001", "kind": "claim", "status": "new", "confidence": "CONFIRMED",
                  "host": "CORP-WS05", "input_call_ids": [41],
                  "statement": "The implant on CORP-WS05 (10.0.0.5) beaconed to 198.51.100.2 and "
                               "evil.example.com",
                  "indicators": [
                      {"type": "ip", "value": "198.51.100.2", "side": "attacker", "sightings": [_sight(41)],
                       "first_seen": "2031-03-01 08:12:00"},
                      {"type": "domain", "value": "evil.example.com", "side": "attacker",
                       "sightings": [_sight(42)]},
                      {"type": "domain", "value": "legacy.example.org", "side": "attacker"}],
                  "indicators_dropped": [{"type": "ip", "value": "203.0.113.9", "reason": "not shown",
                                          "refusal": "presence"}]},
        "C0002": {"id": "C0002", "kind": "claim", "status": "new", "confidence": "LIKELY",
                  "host": "CORP-WS05", "statement": "Persistence through a Run key",
                  "indicators": []},
    }, "edges": []}
    (d / ".atlas" / "claim_graph.json").write_text(json.dumps(graph))
    return d


FINDINGS = [{"type": "finding", "call_id": 50, "claim_id": "C0001", "confidence": "CONFIRMED",
             "description": "beacon", "validated_techniques": [
                 {"technique_id": "T1071.001", "name": "Web Protocols"}]},
            {"type": "finding", "call_id": 51, "claim_id": "C0002", "confidence": "LIKELY",
             "description": "persistence", "validated_techniques": [
                 {"technique_id": "T1547", "name": "Boot Autostart"}]}]


@pytest.fixture(autouse=True)
def _sighted(monkeypatch):
    monkeypatch.setenv("ATLAS_IOC_SIGHTED_CATALOG", "1")


class TestIocExport:
    def test_export_renders_catalog_rows_only(self, tmp_path):
        d = _case(tmp_path)
        out = tmp_path / "exports"
        r = et.write_iocs("CASE-9", FINDINGS, str(out), case_dir=str(d))
        assert r["success"] is True and r["ioc_count"] == 2
        csv_text = (out / "CASE-9.iocs.csv").read_text()
        assert "198.51.100.2" in csv_text and "evil.example.com" in csv_text
        assert "legacy.example.org" not in csv_text and "203.0.113.9" not in csv_text
        stix = json.loads((out / "CASE-9.iocs.stix.json").read_text())
        names = {o["name"] for o in stix["objects"] if o["type"] == "indicator"}
        assert names == {"198.51.100.2", "evil.example.com"}

    def test_private_address_in_finding_text_is_not_exported(self, tmp_path):
        d = _case(tmp_path)
        out = tmp_path / "exports"
        et.write_iocs("CASE-9", FINDINGS, str(out), case_dir=str(d))
        assert "10.0.0.5" not in (out / "CASE-9.iocs.csv").read_text()
        assert "10.0.0.5" not in (out / "CASE-9.iocs.stix.json").read_text()

    def test_stix_valid_from_is_first_seen(self, tmp_path):
        from core.ioc_catalog import build_catalog
        bundle = et.build_stix_bundle("CASE-9", FINDINGS, build_catalog(_case(tmp_path)))
        ind = next(o for o in bundle["objects"] if o["type"] == "indicator" and o["name"] == "198.51.100.2")
        assert ind["valid_from"] == "2031-03-01T08:12:00.000Z"
        assert "standing: cited" in ind["description"] and "CORP-WS05 (call 41)" in ind["description"]

    def test_relationships_point_from_an_indicator_to_its_own_findings_techniques(self, tmp_path):
        from core.ioc_catalog import build_catalog
        bundle = et.build_stix_bundle("CASE-9", FINDINGS, build_catalog(_case(tmp_path)))
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        aps = {o["id"]: o["external_references"][0]["external_id"]
               for o in bundle["objects"] if o["type"] == "attack-pattern"}
        assert rels and all(r["source_ref"].startswith("indicator--") for r in rels)
        assert {aps[r["target_ref"]] for r in rels} == {"T1071.001"}     # no edge to the other finding
        for obj in bundle["objects"]:
            assert obj.get("id", "bundle").split("--")[0] == obj["type"]
            assert obj["spec_version"] == "2.1"
