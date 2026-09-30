"""I3 — access_workflow consumes mount_plan next_work_order."""
from __future__ import annotations

import json
from pathlib import Path

from core.access_workflow import (
    prioritize_tools_for_access_workflow,
    refuse_deep_disk_until_winevt,
    winevt_work_order_pending,
)


def _opened_case(tmp_path: Path) -> Path:
    case = tmp_path / "IsoWO"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / "evidence").mkdir()
    plan = {
        "schema_version": "1.0",
        "case_id": "IsoWO",
        "images": [{
            "path": str(case / "analysis" / "disk.dd"),
            "basename": "disk.dd",
            "status": "opened",
            "opened_tool": "tsk_tsk_fls",
            "origin": "export_raw",
            "next_work_order": [
                "tsk.mmls",
                "tsk.fls",
                "locate winevt/logs/Security.evtx",
                "tsk.icat",
                "ez.evtxecmd",
            ],
            "reason": "exported raw — next: winevt/Security.evtx",
        }],
    }
    (case / ".atlas" / "mount_plan.json").write_text(
        json.dumps(plan), encoding="utf-8",
    )
    (case / "analysis" / "disk.dd").write_bytes(b"\x00" * 16)
    return case


def test_winevt_pending_blocks_sigfind(tmp_path: Path):
    case = _opened_case(tmp_path)
    assert winevt_work_order_pending(case) is True
    msg = refuse_deep_disk_until_winevt(case, "tsk.sigfind")
    assert msg and "access_work_order_pending" in msg
    assert refuse_deep_disk_until_winevt(case, "tsk.indxparse") and \
        "access_work_order_pending" in refuse_deep_disk_until_winevt(
            case, "tsk.indxparse")
    assert refuse_deep_disk_until_winevt(case, "tsk.fls") is None


def test_fls_streak_budget_while_winevt_pending(tmp_path: Path):
    case = _opened_case(tmp_path)
    tr = case / "analysis" / "IsoWO_trace.jsonl"
    lines = []
    for i in range(3):
        lines.append(json.dumps({
            "entry": {
                "type": "tool_call",
                "cmd": f"tsk_fls -r analysis/disk.dd inode={i}",
                "mcp_tool": "tsk_tsk_fls",
            }
        }))
    tr.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # winevt not searched — streak should trip
    assert winevt_work_order_pending(case) is True
    msg = refuse_deep_disk_until_winevt(case, "tsk.fls")
    assert msg and "access_disk_budget" in msg


def test_winevt_search_clears_pending(tmp_path: Path):
    case = _opened_case(tmp_path)
    tr = case / "analysis" / "IsoWO_trace.jsonl"
    tr.write_text(
        json.dumps({
            "entry": {
                "type": "tool_call",
                "cmd": "tsk_fls ... Windows/System32/winevt/logs",
                "mcp_tool": "tsk_tsk_fls",
            }
        }) + "\n",
        encoding="utf-8",
    )
    assert winevt_work_order_pending(case) is False
    assert refuse_deep_disk_until_winevt(case, "tsk.sigfind") is None


def test_priority_puts_winevt_path_first(tmp_path: Path):
    case = _opened_case(tmp_path)
    ordered = prioritize_tools_for_access_workflow(
        case,
        ["tsk.sigfind", "table.table_query", "tsk.fls"],
    )
    assert ordered[0] in ("tsk.fls", "tsk.mmls", "tsk.icat", "ez.evtxecmd")
    assert "tsk.sigfind" in ordered
    assert ordered.index("tsk.fls") < ordered.index("tsk.sigfind")
