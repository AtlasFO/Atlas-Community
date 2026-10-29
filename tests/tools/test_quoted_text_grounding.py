"""The quotation gate reads the calls a finding cites by id over the whole
trace (ATLAS_QUOTE_GATE_CITED_BY_ID); the window of recent calls stays for
the calls it does not cite."""
from __future__ import annotations

from types import SimpleNamespace

from tools._gates import GateContext
from tools._gates import quoted_text_grounding as q

QUOTE = r"C:\Users\jane.doe\AppData\Roaming\svc_update.exe --install"
OLD = {"type": "tool_call", "call_id": 3, "cmd": "<py>:strings_strings_grep", "success": True,
       "stdout_excerpt": f"line 12: {QUOTE}"}


def _ctx(cited, *, spill=None):
    filler = [{"type": "tool_call", "call_id": 100 + i, "cmd": "<py>:vol_pslist", "success": True,
               "stdout_excerpt": f"PID {i}"} for i in range(450)]
    old = {**OLD, **({"stdout_excerpt": "", "stdout_file": str(spill)} if spill else {})}
    entries = [old, *filler]
    return GateContext(
        description=f'The persistence command line was "{QUOTE}".',
        confidence="LIKELY", tier="LIKELY", source="test", linked_call_id=0, tested_hypothesis_id="",
        log=SimpleNamespace(_entries=entries), idx=SimpleNamespace(by_call_id={e["call_id"]: e for e in entries}),
        window=[], input_call_ids=cited)


def test_a_quotation_of_a_cited_call_beyond_the_window_passes():
    assert q.check(_ctx([3])) is None


def test_its_spill_is_read_too(tmp_path):
    spill = tmp_path / "grep.stdout"
    spill.write_text(f"line 12: {QUOTE}\n", encoding="utf-8")
    assert q.check(_ctx([3], spill=spill)) is None


def test_an_uncited_call_beyond_the_window_still_does_not_ground():
    assert q.check(_ctx([])) is not None


def test_switch_off_keeps_the_window_for_cited_calls(monkeypatch):
    monkeypatch.setenv("ATLAS_QUOTE_GATE_CITED_BY_ID", "0")
    assert q.check(_ctx([3])) is not None
