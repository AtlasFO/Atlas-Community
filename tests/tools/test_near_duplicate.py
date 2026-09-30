"""A finding that restates a recorded one is folded, one that sharpens it
is its refinement, and a different event or artifact on the same host
stays a finding of its own."""
from tools import misc


class _Log:
    def __init__(self, *findings):
        self._entries = [{"type": "finding", "call_id": 10 + i, "host": h, "description": d}
                         for i, (h, d) in enumerate(findings)]


OLD = "FTP upload of rhino1.jpg to 192.168.0.5 by user jane on the workstation"


def test_restatement_without_new_content_is_folded():
    log = _Log(("ws1", OLD))
    near = misc._near_duplicate("rhino1.jpg was uploaded by jane over FTP to 192.168.0.5", "WS1", log)
    assert near and near["relation"] == "restates" and near["call_id"] == 10


def test_sharper_statement_is_a_refinement():
    log = _Log(("ws1", OLD))
    near = misc._near_duplicate(OLD + " at 2007-04-19 14:57", "ws1", log)
    assert near and near["relation"] == "refines" and near["call_id"] == 10


def test_another_event_on_the_same_host_is_not_a_duplicate():
    log = _Log(("ws1", OLD))
    assert misc._near_duplicate("FTP login failure from 192.168.0.5 for user jane", "ws1", log) is None


def test_the_same_event_on_another_file_or_host_is_not_a_duplicate():
    log = _Log(("ws1", OLD))
    assert misc._near_duplicate(OLD.replace("rhino1", "rhino4"), "ws1", log) is None
    assert misc._near_duplicate(OLD, "ws2", log) is None


def test_the_guard_can_be_switched_off(monkeypatch):
    monkeypatch.setenv("ATLAS_FINDING_NEAR_DUPLICATE_MIN", "off")
    assert misc._near_duplicate(OLD, "ws1", _Log(("ws1", OLD))) is None
