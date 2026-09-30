"""Increment 3 (T2-3b) — STIX software extraction + load_software().

build_mitre_cache now extracts malware/tool objects and their
intrusion-set --uses--> software relations into mitre_software.json; the loader
exposes them via load_software() for attribution's malware_score.
"""
import json

import pytest

from tools.mitre import build_mitre_cache as bmc
from tools import mitre


def _synthetic_stix():
    return {"objects": [
        {"type": "intrusion-set", "id": "intrusion-set--g", "name": "APT-Test",
         "aliases": ["APT-Test", "EvilBear"],
         "external_references": [{"source_name": "mitre-attack", "external_id": "G9999"}]},
        {"type": "attack-pattern", "id": "attack-pattern--t", "name": "Phishing",
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1566"}]},
        {"type": "malware", "id": "malware--m", "name": "EvilRAT",
         "x_mitre_aliases": ["EvilRAT", "BadRat"],
         "description": "A remote access trojan.\nSecond line.",
         "external_references": [{"source_name": "mitre-attack", "external_id": "S9001"}]},
        {"type": "tool", "id": "tool--x", "name": "Mimikatz",
         "x_mitre_aliases": ["Mimikatz"],
         "external_references": [{"source_name": "mitre-attack", "external_id": "S0002"}]},
        # Deprecated software must be skipped.
        {"type": "malware", "id": "malware--dead", "name": "OldRAT",
         "x_mitre_deprecated": True,
         "external_references": [{"source_name": "mitre-attack", "external_id": "S0000"}]},
        {"type": "relationship", "relationship_type": "uses",
         "source_ref": "intrusion-set--g", "target_ref": "attack-pattern--t"},
        {"type": "relationship", "relationship_type": "uses",
         "source_ref": "intrusion-set--g", "target_ref": "malware--m"},
    ]}


class TestBuildSoftware:
    def test_extracts_software_with_group_and_aliases(self):
        techniques, groups, software, _ = bmc.build_tables(_synthetic_stix(), {})
        assert set(software) == {"S9001", "S0002"}  # deprecated S0000 dropped
        rat = software["S9001"]
        assert rat["type"] == "malware"
        assert rat["group_ids"] == ["G9999"]        # joined via 'uses' relation
        assert "BadRat" in rat["aliases"]           # alias kept
        assert "EvilRAT" not in rat["aliases"]      # own name excluded
        assert rat["description"] == "A remote access trojan."  # first line only

    def test_software_without_group_has_empty_group_ids(self):
        _, _, software, _ = bmc.build_tables(_synthetic_stix(), {})
        assert software["S0002"]["type"] == "tool"
        assert software["S0002"]["group_ids"] == []

    def test_group_still_gets_its_technique(self):
        _, groups, _, _ = bmc.build_tables(_synthetic_stix(), {})
        assert groups["G9999"]["technique_ids"] == ["T1566"]


class TestWriteAndLoadSoftware:
    def test_round_trip(self, tmp_path):
        techniques, groups, software, _ = bmc.build_tables(_synthetic_stix(), {})
        bmc.write_outputs(str(tmp_path), techniques, groups, software, "test://src")
        path = tmp_path / "mitre_software.json"
        assert path.exists()
        doc = json.loads(path.read_text())
        assert doc["_meta"]["format"].startswith("{software_id:")
        loaded = mitre.load_software(str(path))
        assert loaded["software"]["S9001"]["group_ids"] == ["G9999"]

    def test_load_software_missing_file_is_empty(self, tmp_path):
        loaded = mitre.load_software(str(tmp_path / "nope.json"))
        assert loaded == {"software": {}}
