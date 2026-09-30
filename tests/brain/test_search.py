from core.brain import search
from tests.brain.conftest import make_note


def test_title_match_ranks_above_body(brain):
    make_note(brain, "wiki/tools/vol.md", "Volatility Gotchas", type="tool",
              tags="memory-forensics", updated="2026-07-01")
    make_note(brain, "wiki/concepts/other.md", "Timelines", type="concept",
              body="volatility mentioned once", updated="2026-07-05")
    hits = search.search("volatility")
    assert [h.title for h in hits][0] == "Volatility Gotchas"


def test_type_and_tag_filters(brain):
    make_note(brain, "wiki/tools/vol.md", "Volatility", type="tool", tags="memory")
    make_note(brain, "wiki/techniques/dump.md", "Memory dumping", type="technique",
              tags="memory")
    hits = search.search("memory", types=["tool"])
    assert all(h.type == "tool" for h in hits) and hits
    hits = search.search("memory", tags=["memory"])
    assert len(hits) == 2


def test_confidential_excluded(brain):
    make_note(brain, "wiki/tools/c.md", "Secret volatility trick", type="tool",
              classification="confidential")
    assert search.search("volatility") == []
    assert search.search("volatility", include_confidential=True)


def test_no_match_returns_empty(brain):
    make_note(brain, "wiki/tools/vol.md", "Volatility", type="tool")
    assert search.search("zeek") == []
