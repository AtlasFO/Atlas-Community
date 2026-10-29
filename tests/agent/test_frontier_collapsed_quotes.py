"""A collapsed-line quote maps only to a line the call's view
rendered; a sub-range, a range over separate lines, a gapped list and a line a
cut view did not show map nothing (invented rows)."""
import json
from types import SimpleNamespace
from agent.frontier import SubmitApplier
from core import incident_map as IM
from tests.agent.test_frontier_submit import env, _Agent, _item, _ph3  # noqa: F401
from tests.core.test_tool_result_view import _payload, _timeline_rows

T = "2031-01-{:02d} 03:00:01"


def _try(ap, run, quote, cid=31):
    kept, _q = ap._basis([{"call_id": cid, "quote": quote}], run)
    return [k["row_ref"] for k in kept]


def test_rendered_line_maps(env, monkeypatch):
    ap, run, view = _ph3(env, monkeypatch, _payload(_timeline_rows()))
    line = next(r for r in view["rows"] if r.startswith("#1-#13 x13 "))
    assert len(_try(ap, run, line)) == 13


def test_sub_range_never_rendered_maps_nothing(env, monkeypatch):
    ap, run, view = _ph3(env, monkeypatch, _payload(_timeline_rows()))
    q = f"#1-#3 x3 {T.format(1)} .. {T.format(3)} | EVT/WinEVTX"
    assert _try(ap, run, q) == [], "a collapsed line the view never rendered mapped"


def test_range_over_distinct_lines_maps_nothing(env, monkeypatch):
    ap, run, view = _ph3(env, monkeypatch, _payload(_timeline_rows()))
    q = f"#1-#28 x28 {T.format(1)} .. {T.format(26)} | EVT/WinEVTX"
    assert _try(ap, run, q) == [], "a range spanning separate rendered lines mapped"


def test_comma_list_with_a_gap_maps_nothing(env, monkeypatch):
    ap, run, view = _ph3(env, monkeypatch, _payload(_timeline_rows()))
    q = f"#1,#2,#4 x3 {T.format(1)} .. {T.format(4)} | EVT/WinEVTX"
    assert _try(ap, run, q) == [], "a comma list the view never rendered mapped"


def test_cut_view_unshown_line_maps_nothing(env, monkeypatch):
    from core.tool_result_view import render_rows_view
    case, log, m = env
    payload = _payload(_timeline_rows())
    text, note = render_rows_view(payload, 1500, 31, [], tool="table_table_grep")
    saved = json.dumps(payload)
    monkeypatch.setattr(IM.IncidentMap, "_entry", staticmethod(
        lambda cid: {"type": "tool_call", "stdout_excerpt": saved, **note} if int(cid) == 31 else None))
    ap = SubmitApplier(_Agent([]), case, m, _item(log), "join_hit")
    run = SimpleNamespace(calls=[31], seen={31: text})
    shown = json.loads(text)["rows"]
    q = f"#16-#28 x13 {T.format(14)} .. {T.format(26)} | EVT/WinEVTX"
    if not any(r.startswith("#16-#28") for r in shown):
        assert _try(ap, run, q) == [], "a line the cut view did not show mapped"
