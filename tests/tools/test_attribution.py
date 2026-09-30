"""Tests for tools/attribution.py — verify the F1-based ranking surfaces the
expected group from a synthetic finding trace."""
import json
import pytest
from unittest.mock import patch


@pytest.fixture
def log(tmp_path, monkeypatch):
    from core.execution_log import log as _log
    _log.configure("ATTR-TEST", str(tmp_path / "trace.json"))
    return _log


@pytest.fixture
def fake_mitre_tables(tmp_path, monkeypatch):
    """Point tools.mitre to small synthetic tables for deterministic scoring."""
    techniques = {
        "_meta": {"source": "fake", "version": "test"},
        "techniques": {
            "T1059.001": {"name": "PowerShell", "tactic": "Execution",
                          "description": "", "keywords": []},
            "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access",
                          "description": "", "keywords": []},
            "T1021.002": {"name": "SMB", "tactic": "Lateral Movement",
                          "description": "", "keywords": []},
            "T1027": {"name": "Obfuscated Files", "tactic": "Defense Evasion",
                      "description": "", "keywords": []},
            "T1071.001": {"name": "Web Protocols", "tactic": "Command And Control",
                          "description": "", "keywords": []},
            "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery",
                      "description": "", "keywords": []},
        },
    }
    groups = {
        "_meta": {"source": "fake", "version": "test"},
        "groups": {
            "G0001": {
                "name": "TestActor",
                "aliases": ["Phantom Crab"],
                "description": "",
                "technique_ids": ["T1059.001", "T1003.001", "T1021.002",
                                  "T1027", "T1071.001"],
            },
            "G0002": {
                "name": "OtherActor",
                "aliases": [],
                "description": "",
                "technique_ids": ["T1071.001", "T1083"],
            },
        },
    }
    t_path = tmp_path / "tech.json"
    g_path = tmp_path / "groups.json"
    t_path.write_text(json.dumps(techniques))
    g_path.write_text(json.dumps(groups))
    # Bust the lru_cache between tests
    from tools.mitre import _load_json
    _load_json.cache_clear()
    monkeypatch.setenv("ATLAS_MITRE_TABLE", str(t_path))
    monkeypatch.setenv("ATLAS_MITRE_GROUPS", str(g_path))
    monkeypatch.setattr("tools.mitre.DEFAULT_TECHNIQUES_PATH", str(t_path))
    monkeypatch.setattr("tools.mitre.DEFAULT_GROUPS_PATH", str(g_path))


def _seed_findings(log, tids):
    """Inject CONFIRMED findings citing each tid (bypass gates by writing entries directly)."""
    for tid in tids:
        log._entries.append({
            "call_id": log._next_id(),
            "type": "finding",
            "ts": "2026-05-23T00:00:00+00:00",
            "description": f"Confirmed observation of {tid}",
            "confidence": "CONFIRMED",
            "source": "test",
        })
    log._index_version += 1
    log._flush()


def test_attribute_actors_empty_trace(log, fake_mitre_tables):
    from tools.attribution import attribute_actors
    r = attribute_actors()
    assert r["success"] is True
    assert r["observed_tid_count"] == 0
    assert r["candidates"] == []


def test_attribute_actors_high_match(log, fake_mitre_tables):
    from tools.attribution import attribute_actors
    # Seed 5 findings → all 5 of TestActor's techniques covered → HIGH band
    _seed_findings(log, ["T1059.001", "T1003.001", "T1021.002", "T1027", "T1071.001"])
    r = attribute_actors()
    assert r["success"] is True
    assert r["candidates"], f"no candidates returned: {r}"
    top = r["candidates"][0]
    assert top["group_id"] == "G0001"
    assert top["confidence_band"] == "HIGH"
    assert top["overlap_count"] == 5
    # Suggested finding emitted at LIKELY tier
    assert r["suggested_finding"] is not None
    assert r["suggested_finding"]["primary_group_id"] == "G0001"


def test_attribute_actors_below_min_overlap(log, fake_mitre_tables):
    from tools.attribution import attribute_actors
    # Only 1 overlap with each group — under default min_overlap=2
    _seed_findings(log, ["T1083"])
    r = attribute_actors(min_overlap=2)
    assert r["candidates"] == []  # nothing meets threshold


# ── Increment 7 (T2-3c): multi-signal fusion ─────────────────────────────────

def _seed_tool_call(log, cmd, stdout):
    log._entries.append({"call_id": log._next_id(), "type": "tool_call",
                         "ts": "2026-05-23T00:00:00+00:00", "cmd": cmd,
                         "stdout_excerpt": stdout, "success": True})
    log._index_version += 1
    log._flush()


def _write_sidecar(tmp_path, name, doc):
    d = tmp_path / "enrichment"
    d.mkdir(exist_ok=True)
    (d / name).write_text(json.dumps(doc))


class TestInfraFusion:
    def test_matching_adversary_boosts_band(self, log, fake_mitre_tables, tmp_path):
        from tools.attribution import attribute_actors
        _seed_findings(log, ["T1059.001", "T1003.001", "T1021.002"])  # MEDIUM base
        _write_sidecar(tmp_path, "otx_1.2.3.4.json",
                       {"indicator": "1.2.3.4", "adversaries": ["Phantom Crab"]})
        top = attribute_actors()["candidates"][0]
        assert top["group_id"] == "G0001"
        assert top["technique_band"] == "MEDIUM"
        assert top["confidence_band"] == "HIGH"      # bumped one step
        assert top["band_boosted"] is True
        assert top["infra_evidence"] and "Phantom Crab" in top["infra_evidence"][0]
        assert top["components"]["infra"] == 0.5

    def test_misp_galaxy_matches(self, log, fake_mitre_tables, tmp_path):
        from tools.attribution import attribute_actors
        _seed_findings(log, ["T1059.001", "T1003.001", "T1021.002"])
        _write_sidecar(tmp_path, "misp_x.json", {
            "value": "evil.example",
            "galaxy_clusters": [{"galaxy_type": "threat-actor", "value": "TestActor"}],
        })
        top = attribute_actors()["candidates"][0]
        assert top["infra_evidence"] and top["band_boosted"] is True

    def test_non_matching_adversary_no_boost(self, log, fake_mitre_tables, tmp_path):
        from tools.attribution import attribute_actors
        _seed_findings(log, ["T1059.001", "T1003.001", "T1021.002"])
        _write_sidecar(tmp_path, "otx.json", {"adversaries": ["Unrelated Bear"]})
        top = attribute_actors()["candidates"][0]
        assert top["confidence_band"] == "MEDIUM"
        assert top["band_boosted"] is False
        assert top["infra_evidence"] == []


class TestMalwareFusion:
    def test_family_in_yara_output_boosts(self, log, fake_mitre_tables, tmp_path):
        from unittest.mock import patch
        import tools.attribution as attr
        _seed_findings(log, ["T1059.001", "T1003.001", "T1021.002"])
        _seed_tool_call(log, "yara scan_memory_image mem.raw",
                        "rule hit: EvilRAT config strings found")
        sw = {"software": {"S9001": {"name": "EvilRAT", "type": "malware",
                                     "aliases": ["BadRat"], "group_ids": ["G0001"]}}}
        with patch.object(attr, "load_software", return_value=sw):
            top = attr.attribute_actors()["candidates"][0]
        assert top["group_id"] == "G0001"
        assert top["malware_evidence"] and "EvilRAT" in top["malware_evidence"][0]
        assert top["confidence_band"] == "HIGH"
        assert top["components"]["malware"] == 0.5

    def test_stopword_alias_not_matched(self, log, fake_mitre_tables, tmp_path):
        from unittest.mock import patch
        import tools.attribution as attr
        _seed_findings(log, ["T1059.001", "T1003.001", "T1021.002"])
        _seed_tool_call(log, "capa analyze x", "found a generic loader system tool")
        sw = {"software": {"S1": {"name": "System", "type": "tool",
                                  "aliases": ["loader"], "group_ids": ["G0001"]}}}
        with patch.object(attr, "load_software", return_value=sw):
            top = attr.attribute_actors()["candidates"][0]
        assert top["malware_evidence"] == []       # 'system'/'loader' are stopwords


class TestGroundingAndBounds:
    def test_infra_cannot_resurrect_below_threshold_group(self, log, fake_mitre_tables, tmp_path):
        from tools.attribution import attribute_actors
        # Only G0001 techniques observed → G0002 stays below min_overlap.
        _seed_findings(log, ["T1059.001", "T1003.001", "T1021.002", "T1027", "T1071.001"])
        _write_sidecar(tmp_path, "otx.json", {"adversaries": ["OtherActor"]})  # G0002 name
        ids = [c["group_id"] for c in attribute_actors()["candidates"]]
        assert "G0002" not in ids                  # grounding: no technique overlap → absent

    def test_boost_is_at_most_one_step(self, log, fake_mitre_tables, tmp_path):
        from tools.attribution import attribute_actors
        _seed_findings(log, ["T1059.001", "T1003.001"])   # overlap 2 → LOW base
        _write_sidecar(tmp_path, "otx.json", {"adversaries": ["Phantom Crab"]})
        top = attribute_actors()["candidates"][0]
        assert top["technique_band"] == "LOW"
        assert top["confidence_band"] == "MEDIUM"          # LOW→MEDIUM, not HIGH

    def test_backcompat_no_signals_fused_is_scaled_score(self, log, fake_mitre_tables):
        from tools.attribution import attribute_actors
        _seed_findings(log, ["T1059.001", "T1003.001", "T1021.002"])
        r = attribute_actors()
        top = r["candidates"][0]
        assert r["weights"] == {"technique": 0.6, "infra": 0.25, "malware": 0.15}
        assert top["infra_evidence"] == [] and top["malware_evidence"] == []
        assert top["fused_score"] == round(0.6 * top["score"], 4)
        assert top["confidence_band"] == top["technique_band"]


class TestAttributionRequiredGateUnchanged:
    """The fusion changes must not affect the attribution_required gate — it
    keys purely on the attribute_actors tool name in the trace window."""

    def _ctx(self, description, tier, window):
        from tools._gates import GateContext
        return GateContext(description=description, confidence=tier, tier=tier,
                           source="x", linked_call_id=1, tested_hypothesis_id="",
                           log=None, idx=None, window=window)

    def test_gate_fires_without_backing_call(self):
        from tools._gates.attribution_required import check
        out = check(self._ctx("Activity attributed to APT29", "LIKELY", []))
        assert out and out["gate"] == "attribution_required"

    def test_gate_passes_with_backing_call(self):
        from tools._gates.attribution_required import check
        window = [{"type": "tool_call", "cmd": "attribution.attribute_actors top_n=5"}]
        assert check(self._ctx("Activity attributed to APT29", "LIKELY", window)) is None
