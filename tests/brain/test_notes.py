import pytest

from core.brain import frontmatter, notes


def test_new_note_routing(brain):
    path = notes.new_note("tool", "Volatility Symbol Pack Gotcha", tags=["volatility"])
    assert path == brain / "wiki/tools/volatility-symbol-pack-gotcha.md"
    meta, _, warnings = frontmatter.parse(path.read_text())
    assert meta["title"] == "Volatility Symbol Pack Gotcha"
    assert meta["type"] == "tool"
    assert meta["tags"] == ["volatility"]
    assert not any("missing" in w for w in warnings)


def test_new_note_refuses_overwrite(brain):
    notes.new_note("research", "Test Note")
    with pytest.raises(notes.NoteError, match="refusing to overwrite"):
        notes.new_note("research", "Test Note")
    notes.new_note("research", "Test Note", force=True)


def test_new_note_refuses_secrets(brain):
    with pytest.raises(notes.NoteError, match="secret-like"):
        notes.new_note("note", "Creds", body="password=hunter22")
    err = None
    try:
        notes.new_note("note", "Creds2", body="password=hunter22")
    except notes.NoteError as e:
        err = str(e)
    assert err and "hunter22" not in err


def test_new_note_unknown_type(brain):
    with pytest.raises(notes.NoteError, match="unknown note type"):
        notes.new_note("meeting", "X")


def test_run_type_uses_run_summary_template(brain):
    path = notes.new_note("run", "2026-07-07 nitroba train")
    assert path.parent.name == "runs"
    assert "## Findings by Tier" in path.read_text()


def test_environment_note_requires_client(brain):
    with pytest.raises(notes.NoteError, match="require --client"):
        notes.new_note("environment", "ACME AD baseline")


def test_environment_note_routes_under_client_dir(brain):
    path = notes.new_note("environment", "ACME AD baseline",
                          tags=["acme-corp"], client="ACME Corp")
    assert path == brain / "wiki/environments/acme-corp/acme-ad-baseline.md"
    meta, body, _ = frontmatter.parse(path.read_text())
    assert meta["type"] == "environment"
    assert meta["client"] == "acme-corp"
    assert meta["last_verified"]
    assert meta["source"]["type"] == "client_provided"
    assert "Baseline Facts" in body


def test_environment_note_refuses_verdict_language(brain):
    with pytest.raises(notes.NoteError, match="verdict language"):
        notes.new_note("environment", "ACME baseline", client="acme-corp",
                       body="Last incident the attacker dropped a webshell.")
