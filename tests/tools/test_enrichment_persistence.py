"""Increment 3 (T2-3a) — enrichment sidecar persistence + actor/family signals.

otx_lookup and misp_lookup now (a) extract the threat-actor / galaxy signals
attribution fusion needs and (b) persist the full result to
<case>/analysis/enrichment/*.json, no-op outside a case.
"""
import json

import pytest
from unittest.mock import patch, MagicMock

import tools.enrichment as enr


def _resp(status, data):
    m = MagicMock()
    m.status_code = status
    m.json.return_value = data
    return m


class TestAnalysisDirAndPersist:
    def test_persist_writes_sidecar_when_case_configured(self, tmp_path, monkeypatch):
        monkeypatch.setattr(enr, "_analysis_dir", lambda: str(tmp_path))
        p = enr._persist("otx", "1.2.3.4", {"success": True, "x": 1})
        assert p is not None
        written = json.loads((tmp_path / "enrichment" / "otx_1.2.3.4.json").read_text())
        assert written["x"] == 1

    def test_persist_noop_without_case(self, monkeypatch):
        monkeypatch.setattr(enr, "_analysis_dir", lambda: None)
        assert enr._persist("otx", "1.2.3.4", {"success": True}) is None

    def test_safe_name_sanitizes_indicator(self):
        assert enr._safe_name("https://evil.example/x") == "https_evil.example_x"
        assert enr._safe_name("") == "indicator"


class TestOtxAdversaries:
    def test_extracts_adversaries_and_persists(self, tmp_path, monkeypatch):
        monkeypatch.setenv("OTX_API_KEY", "k")
        monkeypatch.setattr(enr, "_analysis_dir", lambda: str(tmp_path))
        body = {"pulse_info": {"count": 2, "pulses": [
            {"tags": ["apt"], "malware_families": ["Emotet"], "adversary": "APT28"},
            {"tags": ["c2"], "malware_families": [], "adversary": ""},
        ]}}
        with patch("httpx.request", return_value=_resp(200, body)):
            r = enr.otx_lookup("evil.example", "domain")
        assert r["success"] and r["adversaries"] == ["APT28"]
        assert "Emotet" in r["malware_families"]
        # Sidecar written and path surfaced.
        assert r["sidecar_path"].endswith("enrichment/otx_evil.example.json")
        assert (tmp_path / "enrichment" / "otx_evil.example.json").exists()

    def test_no_sidecar_key_without_case(self, monkeypatch):
        monkeypatch.setenv("OTX_API_KEY", "k")
        monkeypatch.setattr(enr, "_analysis_dir", lambda: None)
        body = {"pulse_info": {"count": 0, "pulses": []}}
        with patch("httpx.request", return_value=_resp(200, body)):
            r = enr.otx_lookup("evil.example", "domain")
        assert r["success"] and "sidecar_path" not in r
        assert r["adversaries"] == []


class TestMispGalaxies:
    def test_extracts_galaxy_clusters_and_tags(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MISP_URL", "https://misp.example")
        monkeypatch.setenv("MISP_API_KEY", "k")
        monkeypatch.setattr(enr, "_analysis_dir", lambda: str(tmp_path))
        body = {"response": {"Attribute": [
            {
                "type": "ip-dst", "value": "1.2.3.4", "event_id": "5",
                "Tag": [{"name": 'misp-galaxy:threat-actor="APT29"'},
                        {"name": "tlp:red"}],
                "Galaxy": [{
                    "type": "threat-actor",
                    "GalaxyCluster": [{
                        "value": "APT29",
                        "tag_name": 'misp-galaxy:threat-actor="APT29"',
                    }],
                }],
            },
            # Duplicate cluster on another attribute must be de-duplicated.
            {
                "type": "domain", "value": "evil.example", "event_id": "5",
                "Galaxy": [{
                    "type": "threat-actor",
                    "GalaxyCluster": [{"value": "APT29"}],
                }],
            },
        ]}}
        with patch("httpx.request", return_value=_resp(200, body)):
            r = enr.misp_lookup("1.2.3.4")
        assert r["success"] and r["match_count"] == 2
        assert 'misp-galaxy:threat-actor="APT29"' in r["tags"]
        assert "tlp:red" in r["tags"]
        clusters = {(c["galaxy_type"], c["value"]) for c in r["galaxy_clusters"]}
        assert clusters == {("threat-actor", "APT29")}  # de-duped
        assert (tmp_path / "enrichment" / "misp_1.2.3.4.json").exists()
