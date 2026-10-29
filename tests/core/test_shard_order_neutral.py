"""ATLAS_SHARD_ORDER_NEUTRAL: a directory's files rank by the words
of the focus text they hold, then by name; the refusal states the total and
names the listing that pages through the rest. Invented channel names only."""
from __future__ import annotations

from pathlib import Path

from core.input_scale import _affinity_score, rank_shards

NAMES = ["Application.evtx", "Security.evtx", "System.evtx", "Microsoft-Windows-Alpha%4Operational.evtx",
         "Microsoft-Windows-Beta%4Admin.evtx", "Vendor-Gamma%4Diagnostic.evtx"]


def _dir(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    for n in NAMES:
        (d / n).write_bytes(b"x" * (10 + len(n)))
    return [d / n for n in NAMES]


def test_without_focus_the_order_is_by_name(tmp_path):
    shards = rank_shards(_dir(tmp_path), focus_text="", cap=3)
    assert [Path(s["path"]).name for s in shards] == sorted(NAMES, key=str.lower)[:3]
    assert all(s["affinity"] == 0 for s in shards)


def test_a_focus_word_in_one_name_puts_it_first(tmp_path):
    shards = rank_shards(_dir(tmp_path), focus_text="which logons reached the Gamma service", cap=3)
    assert Path(shards[0]["path"]).name == "Vendor-Gamma%4Diagnostic.evtx"
    assert _affinity_score("Security.evtx", "authentication from a remote host") == 0


def test_the_refusal_states_the_total_and_the_listing(tmp_path, monkeypatch):
    from core import input_scale as I
    out = I._shards_more(str(tmp_path / "logs"), 6, 3)
    assert out["shards_total"] == 6 and "misc.list_evidence_dir" in out["shards_more"]
    monkeypatch.setenv("ATLAS_SHARD_ORDER_NEUTRAL", "0")
    assert I._shards_more(str(tmp_path / "logs"), 6, 3) == {}
    assert _affinity_score("Security.evtx", "") == 5.0


def test_every_occurrence_of_a_focus_word_counts():
    assert _affinity_score("Vendor-Gamma%4Diagnostic.evtx", "gamma gamma") == 3.0
