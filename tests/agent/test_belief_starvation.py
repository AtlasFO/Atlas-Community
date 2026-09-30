"""Belief-starvation latch — formalise hits before more gathering."""
from __future__ import annotations

from agent.belief_starvation import (
    classify_result_as_contact,
    findings_recorded,
    format_starvation_message,
    is_substantive_contact,
    starvation_latched,
    starvation_refusal,
    substantive_contact_count,
    tool_allowed_while_latched,
)


def _table_hit(call_id: int = 1, rows: int = 5) -> dict:
    return {
        "type": "tool_call",
        "call_id": call_id,
        "mcp_tool": "table_table_query",
        "cmd": "table_table_query path=evidence/events.csv",
        "success": True,
        "output": {
            "success": True,
            "matched_rows": rows,
            "returned_rows": min(rows, 50),
            "path": "evidence/events.csv",
        },
    }


def test_substantive_contact_requires_hits():
    assert is_substantive_contact(_table_hit(rows=3))
    zero = _table_hit(rows=0)
    zero["output"] = {
        "success": True, "matched_rows": 0, "valid_zero": True,
    }
    assert not is_substantive_contact(zero)


def test_unknown_columns_is_not_a_contact():
    e = {
        "type": "tool_call",
        "mcp_tool": "table_table_query",
        "success": False,
        "output": {"success": False, "gate": "unknown_columns"},
    }
    assert not is_substantive_contact(e)


def test_parser_success_counts_without_row_field():
    e = {
        "type": "tool_call",
        "mcp_tool": "ez_evtxecmd",
        "cmd": "ez_evtxecmd --file evidence/host/Security.evtx",
        "success": True,
        "output": {"success": True, "csv": "analysis/out.csv"},
    }
    assert is_substantive_contact(e)


def test_latch_engages_after_threshold_with_zero_findings():
    entries = [_table_hit(i, rows=2) for i in range(1, 4)]
    assert substantive_contact_count(entries) == 3
    assert findings_recorded(entries) == 0
    assert starvation_latched(entries) is True


def test_latch_clears_when_finding_recorded():
    entries = [_table_hit(i, rows=2) for i in range(1, 4)]
    entries.append({
        "type": "finding",
        "call_id": 99,
        "description": "user01 created a file on WS01",
        "confidence": "LIKELY",
    })
    assert starvation_latched(entries) is False


def test_successful_record_finding_tool_clears_via_count():
    entries = [_table_hit(i, rows=2) for i in range(1, 4)]
    entries.append({
        "type": "tool_call",
        "mcp_tool": "misc_record_finding",
        "success": True,
        "output": {"success": True},
    })
    assert findings_recorded(entries) >= 1
    assert starvation_latched(entries) is False


def test_multi_host_paths_are_irrelevant_to_latch():
    """Latch is about finding formalisation, not host basenames."""
    a = _table_hit(1, rows=4)
    a["cmd"] = "table_table_query path=evidence/WS01/logs.csv"
    b = _table_hit(2, rows=4)
    b["cmd"] = "table_table_query path=evidence/WS02/logs.csv"
    c = _table_hit(3, rows=4)
    c["cmd"] = "table_table_query path=evidence/WS03/logs.csv"
    assert starvation_latched([a, b, c]) is True


def test_allowed_tools_while_latched():
    assert tool_allowed_while_latched("misc_record_finding")
    assert tool_allowed_while_latched("misc.update_investigation_task")
    assert tool_allowed_while_latched("table_table_schema")
    assert tool_allowed_while_latched("dair_dair_assess")
    assert not tool_allowed_while_latched("table_table_query")
    assert not tool_allowed_while_latched("tsk_tsk_fls")
    assert not tool_allowed_while_latched("img_vmdk_export_raw")


def test_refusal_payload_is_protocol_gate():
    import json
    raw = starvation_refusal("table_table_query", contacts=3)
    data = json.loads(raw)
    assert data["gate"] == "belief_starvation"
    assert data["redirect_to"] == "misc.record_finding"
    assert "record_finding" in data["error"]


def test_format_message_mentions_latch():
    msg = format_starvation_message(contacts=5, findings=0)
    assert "belief-starvation latch" in msg
    assert "record_finding" in msg


def test_classify_result_as_contact_from_loop_payload():
    ok = classify_result_as_contact(
        "table_table_query",
        '{"success": true, "matched_rows": 12, "returned_rows": 12}',
    )
    assert ok is True
    bad = classify_result_as_contact(
        "table_table_query",
        '{"success": false, "gate": "unknown_columns"}',
    )
    assert bad is False
