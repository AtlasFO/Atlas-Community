"""One indicator count for a case: the catalog's total, the typed rows the
report and the IOC export count. The Overview's summary and the IoCs tab
both use it; the case's own assets, the rows to review before use and the
values named but not seen are listed beside it and counted apart. A
synthetic catalog (invented values) stands in for build_catalog."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from core import ioc_catalog
from dashboard import read_models

ROOT = Path(__file__).resolve().parents[2]

CATALOG = {
    "frame": "incident", "total": 2, "review_total": 1, "affected_total": 1, "context_total": 1,
    "beliefs_considered": 3, "sighted": False,
    "iocs": [{"value": "203.0.113.7", "category": "ip", "role": "attacker_infra",
              "confidence": "LIKELY", "hosts": ["CORP-WS01"], "claim_ids": ["c1"]},
             {"value": "jane.doe", "category": "account", "role": "attacker_account",
              "confidence": "CONFIRMED", "hosts": ["CORP-WS01"], "claim_ids": ["c2"]}],
    "review": [{"value": "evil.example.com", "category": "domain", "confidence": "SUSPECTED", "hosts": []}],
    "affected_assets": [{"value": "CORP-DC01", "category": "host", "confidence": "LIKELY", "hosts": []}],
    "context": [{"value": "198.51.100.9", "category": "ip", "hosts": []}],
}


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "CASE-A"
    (d / ".atlas").mkdir(parents=True)
    (d / ".atlas" / "claim_graph.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(ioc_catalog, "build_catalog", lambda c: json.loads(json.dumps(CATALOG)))
    read_models._ioc_cache.clear()
    return str(d)


def test_the_overview_counts_the_typed_rows_and_names_the_rest(case):
    s = read_models.ioc_summary(case)
    assert s["total"] == 2 == sum(g["count"] for g in s["groups"])
    assert {g["title"] for g in s["others"]} == {"Affected assets", "Review before use",
                                                 "Named, not seen in this evidence"}
    assert (s["review_total"], s["affected_total"], s["context_total"]) == (1, 1, 1)


def test_the_iocs_tab_marks_which_groups_count(case):
    c = read_models.ioc_catalog_with_context(case)
    assert c["total"] == 2
    assert sum(len(g["iocs"]) for g in c["groups"] if g["counted"]) == 2
    assert [g["title"] for g in c["groups"] if not g["counted"]] == [
        "Affected assets", "Review before use", "Named, not seen in this evidence"]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_iocs_headline_is_the_same_count(case, tmp_path):
    payload = tmp_path / "iocs.json"
    payload.write_text(json.dumps(read_models.ioc_catalog_with_context(case)), encoding="utf-8")
    proc = subprocess.run(["node", str(ROOT / "tests/dashboard/iocs_harness.js"),
                           str(ROOT / "dashboard/iocs.html"), str(payload)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "iocs harness: ok" in proc.stdout
