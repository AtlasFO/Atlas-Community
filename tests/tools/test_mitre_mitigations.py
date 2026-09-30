"""MITRE's mitigations reach Atlas through the same builder as the other
tables, are looked up per technique with sub-technique fallback, and turn a
substantiated finding's techniques into derived recommendations."""
import json

import pytest

from core import claim_graph as cg
from core.recommendations import build_catalog, derive_from_claim, derive_from_finding_text
from tools.mitre import build_mitre_cache as builder
from tools.mitre import mitigations_for


def _stix():
    def ref(eid):
        return [{"source_name": "mitre-attack", "external_id": eid}]
    return {"objects": [
        {"type": "x-mitre-collection", "x_mitre_version": "99.0"},
        {"type": "attack-pattern", "id": "ap-1", "name": "Data Encrypted for Impact",
         "external_references": ref("T1486"),
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "impact"}]},
        {"type": "attack-pattern", "id": "ap-2", "name": "Valid Accounts",
         "external_references": ref("T1078"),
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "persistence"}]},
        {"type": "course-of-action", "id": "coa-1", "name": "Data Backup",
         "description": "Take and securely store backups. Restore from them.",
         "external_references": ref("M1053")},
        {"type": "course-of-action", "id": "coa-2", "name": "Multi-factor Authentication",
         "description": "Use two or more pieces of evidence.", "external_references": ref("M1032")},
        {"type": "course-of-action", "id": "coa-legacy", "name": "Old per-technique CoA",
         "external_references": ref("T1486")},
        {"type": "relationship", "relationship_type": "mitigates", "source_ref": "coa-1", "target_ref": "ap-1"},
        {"type": "relationship", "relationship_type": "mitigates", "source_ref": "coa-2", "target_ref": "ap-2"},
        {"type": "relationship", "relationship_type": "mitigates", "source_ref": "coa-2", "target_ref": "ap-1",
         "revoked": True},
    ]}


class TestBuilder:
    def test_mitigations_and_their_techniques_are_extracted(self):
        _, _, _, mit = builder.build_tables(_stix(), {})
        assert set(mit["mitigations"]) == {"M1053", "M1032"}    # the legacy CoA is skipped
        assert mit["mitigations"]["M1053"]["technique_ids"] == ["T1486"]
        assert mit["by_technique"] == {"T1078": ["M1032"], "T1486": ["M1053"]}  # revoked edge ignored

    def test_the_fourth_table_is_written_with_the_others(self, tmp_path):
        t, g, s, mit = builder.build_tables(_stix(), {})
        builder.write_outputs(str(tmp_path), t, g, s, "src", "v99", mitigations=mit)
        doc = json.loads((tmp_path / "mitre_mitigations.json").read_text())
        assert doc["_meta"]["version"] == "v99" and "by_technique" in doc


@pytest.fixture
def table(tmp_path):
    p = tmp_path / "mit.json"
    p.write_text(json.dumps({
        "mitigations": {
            "M1053": {"name": "Data Backup", "description": "Take backups. Store them.",
                      "technique_ids": ["T1486"]},
            "M1030": {"name": "Network Segmentation", "description": "Segment the network.",
                      "technique_ids": ["T1021", "T1486"]},
            "M1032": {"name": "Multi-factor Authentication", "description": "Use MFA.",
                      "technique_ids": ["T1078", "T1021"]},
            "M1055": {"name": "Do Not Mitigate", "description": "Nothing.", "technique_ids": ["T1078"]},
        },
        "by_technique": {"T1486": ["M1030", "M1053"], "T1021": ["M1030", "M1032"],
                         "T1078": ["M1032", "M1055"]},
    }))
    return str(p)


class TestLookup:
    def test_most_widely_applicable_first_and_subtechnique_fallback(self, table):
        out = mitigations_for(["T1486", "T1021.001"], path=table)
        assert [m["id"] for m in out][:1] == ["M1030"]          # covers both
        assert next(m for m in out if m["id"] == "M1030")["technique_ids"] == ["T1021.001", "T1486"]

    def test_unknown_techniques_yield_nothing(self, table):
        assert mitigations_for(["T9999"], path=table) == []


class TestDerivation:
    def _case(self, tmp_path):
        d = tmp_path / "case"
        (d / ".atlas").mkdir(parents=True)
        return d

    def test_a_claim_naming_techniques_earns_their_mitigations(self, tmp_path, table):
        case = self._case(tmp_path)
        c = cg.add_claim(case, statement="Files were encrypted across the share (T1486) after "
                                         "lateral movement over SMB (T1021)",
                         confidence="CONFIRMED", host="FILE01")["node_id"]
        # a mitigation with nothing to act on is a reference, not a row
        out = derive_from_claim(case, c, mitigations_path=table)
        assert out["techniques"] == ["T1021", "T1486"] and out["recorded"] == []
        assert cg.set_claim_indicators(case, c, [{"type": "host", "value": "FILE01", "side": "victim"},
                                                 {"type": "account", "value": "jane", "side": "victim"}])["success"]
        out = derive_from_claim(case, c, mitigations_path=table)
        rows = {r["action"]: r for r in build_catalog(case)["recommendations"]}
        # one row per technique, the first mitigation with objects, its text as the rationale
        assert set(rows) == {"Harden the systems the finding names against T1021: FILE01 (M1030 Network Segmentation)",
                             "Harden the systems the finding names against T1486: FILE01 (M1030 Network Segmentation)"}
        for r in rows.values():
            assert (r["phase"], r["urgency"], r["objects"]) == ("harden", "later", ["FILE01"])
            assert r["source"] == "derived" and r["basis"][0]["id"] == c
            assert r["rationale"].startswith("Segment the network. MITRE ATT&CK mitigation M1030")
        assert not any("Data Backup" in a for a in rows)

    def test_do_not_mitigate_is_skipped_and_derivation_folds(self, tmp_path, table):
        case = self._case(tmp_path)
        c = cg.add_claim(case, statement="Valid account abuse (T1078)", confidence="LIKELY")["node_id"]
        assert cg.set_claim_indicators(case, c, [{"type": "account", "value": "jane", "side": "victim"}])["success"]
        first = derive_from_claim(case, c, mitigations_path=table)
        assert first["recorded"] and not first["folded"]
        again = derive_from_claim(case, c, mitigations_path=table)
        assert again["recorded"] == [] and again["folded"] == first["recorded"]
        actions = [r["action"] for r in build_catalog(case)["recommendations"]]
        assert not any("Do Not Mitigate" in a for a in actions)

    def test_a_claim_without_techniques_derives_nothing(self, tmp_path, table):
        case = self._case(tmp_path)
        c = cg.add_claim(case, statement="a logon at 10:54", confidence="CONFIRMED")["node_id"]
        assert derive_from_claim(case, c, mitigations_path=table)["recorded"] == []
        assert build_catalog(case)["total"] == 0

    def test_the_bundled_table_covers_the_impact_technique(self):
        """The shipped table, not a fixture: a real T1486 finding gets Data Backup."""
        from pathlib import Path
        p = Path("share/.common/mitre_mitigations.json")
        assert "M1053" in (mitigations := [m["id"] for m in mitigations_for(["T1486"], path=str(p))]), mitigations


class TestFindingTextDerivation:
    """The same intake threat-class table, matched against a finding's own
    wording instead of the case intake — no MITRE technique id required."""

    def _case(self, tmp_path):
        d = tmp_path / "case"
        (d / ".atlas").mkdir(parents=True)
        return d

    def test_a_finding_matching_a_threat_class_earns_its_precautions(self, tmp_path):
        case = self._case(tmp_path)
        statement = "Files across the share were encrypted and a ransom note appeared"
        c = cg.add_claim(case, statement=statement, confidence="CONFIRMED", host="FILE01")["node_id"]
        out = derive_from_finding_text(case, c, statement, host="FILE01")
        assert out["classes"] == ["ransomware"] and out["recorded"]
        rows = build_catalog(case)["recommendations"]
        assert rows and all(r["source"] == "derived" and r["basis"][0]["id"] == c for r in rows)
        # a single-host finding cannot earn an estate-wide recommendation on its own
        assert all(r["scope"] == "host" for r in rows)

    def test_derivation_folds_on_repeat(self, tmp_path):
        case = self._case(tmp_path)
        statement = "an account was compromised after phishing"
        c = cg.add_claim(case, statement=statement, confidence="LIKELY", host="WKS01")["node_id"]
        first = derive_from_finding_text(case, c, statement, host="WKS01")
        assert first["recorded"] and not first["folded"]
        again = derive_from_finding_text(case, c, statement, host="WKS01")
        assert again["recorded"] == [] and again["folded"] == first["recorded"]

    def test_a_finding_matching_no_class_derives_nothing(self, tmp_path):
        case = self._case(tmp_path)
        c = cg.add_claim(case, statement="a logon at 10:54", confidence="CONFIRMED")["node_id"]
        assert derive_from_finding_text(case, c, "a logon at 10:54")["recorded"] == []
        assert build_catalog(case)["total"] == 0

    def test_an_estate_scoped_claim_can_earn_an_estate_scoped_precaution(self, tmp_path):
        case = self._case(tmp_path)
        statement = "Ransomware encrypted files across the domain"
        c = cg.add_claim(case, statement=statement, confidence="CONFIRMED", scope="estate")["node_id"]
        out = derive_from_finding_text(case, c, statement)
        rows = {r["id"]: r for r in build_catalog(case)["recommendations"]}
        assert out["recorded"] and any(rows[nid]["scope"] == "estate" for nid in out["recorded"])
