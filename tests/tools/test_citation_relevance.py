"""A finding whose cited calls do not contain the identifiers it rests on,
while another call does, gets an advisory naming that call. The finding is
recorded either way; nothing blocks."""
from tools import misc


class _Log:
    def __init__(self, *calls):
        # calls: (call_id, cmd, excerpt)
        self._entries = [{"type": "tool_call", "call_id": c, "success": True,
                          "cmd": cmd, "stdout_excerpt": ex} for c, cmd, ex in calls]

    def index(self):
        return {e["call_id"]: e for e in self._entries}


def test_advisory_points_at_the_call_that_holds_the_identifier():
    log = _Log(
        (65, "strings -a usb_unallocated.bin", "filler filler filler"),
        (30, "strings -a capture.log", "the account came from 198.51.100.53 on 2031-04-21"),
    )
    out = misc._citation_relevance_advisory(
        "Activity from 198.51.100.53 on 2031-04-21 is in the log", [65], 65, log)
    assert out is not None
    assert out["suggested_call_ids"] == [30]
    assert "198.51.100.53" in out["advisory"] or "2031-04-21" in out["advisory"]


def test_no_advisory_when_the_cited_call_carries_the_identifier():
    log = _Log((30, "strings capture.log", "connection from 198.51.100.53 seen"))
    assert misc._citation_relevance_advisory(
        "traffic from 198.51.100.53", [30], 30, log) is None


def test_no_advisory_without_identifiers_in_the_claim():
    log = _Log((30, "strings x", "some output"))
    assert misc._citation_relevance_advisory(
        "the archive was truncated and could not be opened", [30], 30, log) is None


def test_no_advisory_when_nothing_in_the_trace_matches():
    log = _Log((30, "strings x", "unrelated output"))
    assert misc._citation_relevance_advisory(
        "traffic from 10.0.0.9 at 2020-01-02", [30], 30, log) is None
