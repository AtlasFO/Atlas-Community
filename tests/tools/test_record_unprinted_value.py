"""The record-time citation refusal the re-seated live probe
(devtools/validation/live_refusal_probe.py, withdraw_unsupported) sets up.
A finding naming an address and a family name no cited call printed is
refused when it is recorded, with both objections; the report gate is no
longer where it is caught. Invented values."""
from __future__ import annotations

import pytest
from tests._edition import DEVTOOLS_SHIPPED, NO_DEVTOOLS
from unittest.mock import patch


@pytest.mark.skipif(not DEVTOOLS_SHIPPED, reason=NO_DEVTOOLS)
def test_a_finding_naming_values_no_call_printed_is_refused_at_record_time(monkeypatch, tmp_path):
    import tempfile
    from devtools.validation import live_refusal_probe as P
    from tools.misc import record_finding
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    case, log, ids = P._unprinted_case()
    with patch("core.execution_log.log", log):
        r = record_finding(description=P.WITHDRAW_UNSUPPORTED, confidence="LIKELY", source="vol.pslist",
                           linked_call_id=ids["pslist"], input_call_ids=[ids["pslist"]],
                           supporting_evidence=P.PSLIST_ROW, host="WORKSTATION")
    assert r["success"] is False and "198.51.100.7" in r.get("uncited_claims", [])
    assert "external_knowledge_grounding" in [a.get("detail_gate") for a in r.get("also_refused_by") or []]
    with patch("core.execution_log.log", log):
        ok = record_finding(description="svc_update.exe (pid 4412) runs on the workstation, parent services.exe",
                            confidence="LIKELY", source="vol.pslist", linked_call_id=ids["pslist"],
                            input_call_ids=[ids["pslist"]], supporting_evidence=P.PSLIST_ROW, host="WORKSTATION")
    assert ok["success"] is True                      # what the output shows is recorded
