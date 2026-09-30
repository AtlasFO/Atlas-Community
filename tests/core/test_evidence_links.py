"""Evidence Links — CASE.md host/path map for Atlas focus seeds."""
from __future__ import annotations

from pathlib import Path

from core.evidence_links import (
    parse_evidence_links,
    path_link_boost,
    resolve_host_label,
    sync_evidence_links,
)
from core.investigation_plan import build_investigation_plan
from core.investigation_tasks import parse_case_requests


SAMPLE = """# Case: Demo

**Case ID:** Demo

## Investigation Requests

- What happened on host FILESRV01?

## Evidence Links

| Label | Kind | Path | Notes |
|-------|------|------|-------|
| FILESRV02 | disk | evidence/FILESRV02/FILESRV02.vmdk | descriptor |
| FILESRV01 | alias | FILESRV02 | EDR name |
| user01 | principal | | compromised |
| VPN/EDR | tabular | evidence/ | CSVs at root |

## Other

- not a request from evidence links
"""


def test_parse_table_and_alias():
    data = parse_evidence_links(SAMPLE)
    assert data["aliases"]["FILESRV01"] == "FILESRV02"
    assert "FILESRV02" in data["hosts"]
    assert "evidence/FILESRV02/FILESRV02.vmdk" in data["paths"]
    assert "user01" in data["principals"]
    kinds = {e["label"]: e["kind"] for e in data["entries"]}
    assert kinds["FILESRV02"] == "disk"
    assert kinds["FILESRV01"] == "alias"


def test_parse_bullets_and_arrow():
    md = """## Evidence Links

- WEB01 | disk | evidence/WEB01/disk.e01 | E01
- WEB-OLD -> WEB01 | alias | | former name
"""
    data = parse_evidence_links(md)
    assert data["aliases"]["WEB-OLD"] == "WEB01"
    assert "evidence/WEB01/disk.e01" in data["paths"]


def test_requests_ignore_evidence_links_section():
    reqs = parse_case_requests(SAMPLE)
    assert reqs == ["What happened on host FILESRV01?"]


def test_html_comment_bullets_not_parsed_as_links():
    md = """## Evidence Links

| Label | Kind | Path | Notes |
|-------|------|------|-------|
| HOST1 | disk | evidence/HOST1/a.vmdk | ok |

<!--
CASE.md docs:
  - investigation_tasks.json
  - claim_graph.json
-->
"""
    data = parse_evidence_links(md)
    assert len(data["entries"]) == 1
    assert data["entries"][0]["label"] == "HOST1"


def test_sync_and_plan_seeds(tmp_path: Path):
    case = tmp_path / "Demo"
    case.mkdir()
    (case / "CASE.md").write_text(SAMPLE, encoding="utf-8")
    (case / "evidence").mkdir()
    (case / "evidence" / "FILESRV02").mkdir()
    (case / "evidence" / "FILESRV02" / "FILESRV02.vmdk").write_text("x")

    data = sync_evidence_links(case, persist=True)
    assert (case / ".atlas" / "evidence_links.json").is_file()
    assert resolve_host_label(case, "FILESRV01") == "FILESRV02"
    assert path_link_boost(
        "evidence/FILESRV02/FILESRV02.vmdk", case
    ) >= 5.0

    plan = build_investigation_plan(case, {"case_id": "Demo"}, persist=True)
    assert "FILESRV02" in (plan.get("focus_hosts") or [])
    assert "FILESRV01" in (plan.get("focus_hosts") or [])
    assert any(
        "FILESRV02.vmdk" in p for p in (plan.get("focus_evidence") or [])
    )
    el = plan.get("evidence_links") or {}
    assert el.get("aliases", {}).get("FILESRV01") == "FILESRV02"
