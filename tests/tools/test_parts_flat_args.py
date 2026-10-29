"""ATLAS_PARTS_FLAT_ARGS: one part closed or limited through flat
parameters with the limitation basis as an enum in the schema; the parts
object stays for several parts; both shapes at once are refused. Invented
fixtures only."""
from __future__ import annotations

import asyncio

from core.investigation_tasks import reconcile_case_md
from tools.misc import update_investigation_task

upd = getattr(update_investigation_task, "fn", update_investigation_task)


def _case(tmp_path):
    case = tmp_path / "X"
    (case / ".atlas").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID:** X\n\nAccounts are out of scope for this engagement.\n\n"
                                  "## Investigation Requests\n- Baseline — timezone, accounts.\n", encoding="utf-8")
    return case, reconcile_case_md(case)["tasks"][0]["id"]


def test_one_part_is_limited_through_the_flat_parameters(tmp_path):
    case, tid = _case(tmp_path)
    r = upd(tid, case_dir=str(case), part="p2", limitation_basis="out_of_scope",
            limitation_reason="the brief puts the accounts out of scope")
    assert r["success"] and r["task"]["parts"][1]["status"] == "limited"
    assert r["task"]["parts"][1]["limitation"]["basis"] == "out_of_scope"


def test_both_shapes_at_once_are_refused_and_a_part_must_be_named(tmp_path):
    case, tid = _case(tmp_path)
    r = upd(tid, case_dir=str(case), part="p2", limitation_basis="out_of_scope",
            parts={"p1": {"claim_ids": ["C0001"]}})
    assert not r["success"] and "not both" in r["error"]
    r = upd(tid, case_dir=str(case), limitation_basis="examined", limitation_reason="the hive was read, no answer")
    assert not r["success"] and "part= names the part" in r["error"]


def test_the_basis_is_an_enum_in_the_tool_schema():
    import server
    from fastmcp import Client

    async def schema():
        async with Client(server.mcp) as c:
            tools = await c.list_tools()
        t = next(t for t in tools if t.name.endswith("update_investigation_task"))
        return getattr(t, "input_schema", None) or t.inputSchema
    props = asyncio.run(schema())["properties"]
    basis = props["limitation_basis"]
    enum = basis.get("enum") or next(o.get("enum") for o in basis.get("anyOf", []) if o.get("enum"))
    assert set(enum) == {"source_absent", "examined", "unreadable", "out_of_scope"}
    assert "part" in props and "part_claim_ids" in props and "limitation_call_ids" in props


def test_off_the_flat_form_is_refused_and_a_basis_spelling_is_read(tmp_path, monkeypatch):
    case, tid = _case(tmp_path)
    monkeypatch.setenv("ATLAS_PARTS_FLAT_ARGS", "0")
    r = upd(tid, case_dir=str(case), part="p2", limitation_basis="out_of_scope", limitation_reason="r")
    assert not r["success"] and "off in this run" in r["error"]
    from core.tool_arg_coerce import coerce_value
    prop = {"anyOf": [{"enum": ["source_absent", "examined", "unreadable", "out_of_scope"], "type": "string"},
                      {"type": "null"}]}
    assert coerce_value("source absent", prop) == "source_absent"
    assert coerce_value("Out-Of-Scope", prop) == "out_of_scope" and coerce_value("nope", prop) == "nope"


def test_a_hybrid_parts_entry_is_refused_not_half_applied(tmp_path):
    case, tid = _case(tmp_path)
    r = upd(tid, case_dir=str(case), parts={"p2": {"limitation_basis": "out_of_scope",
                                                    "limitation_reason": "the brief excludes it"}})
    assert not r["success"] and r["gate"] == "task_part_args" and "limitation_basis" in r["error"]
