"""The shipped provider profiles are written to be edited by hand: each
names its schema for editors, says where its fields are explained and how a
first edit fails, and explains every key it sets. Their notes speak to the
user, never of Atlas's code."""
from __future__ import annotations

import re

import pytest

from core import provider_profiles as pp

FILES = sorted(pp.SHIPPED_DIR.glob("*.toml"))
KEY = re.compile(r"^\s*[A-Za-z0-9_-]+\s*=")


def _key_lines(text: str):
    """(index, line) of every key line outside a multi-line string."""
    lines, inside = text.splitlines(), False
    for i, line in enumerate(lines):
        if inside:
            inside = line.count('"""') % 2 == 0
            continue
        if KEY.match(line):
            yield i, line, lines
            inside = line.count('"""') % 2 == 1


def _trailing_comment(line: str) -> bool:
    quoted = False
    for ch in line:
        if ch == '"':
            quoted = not quoted
        elif ch == "#" and not quoted:
            return True
    return False


def test_every_shipped_profile_still_loads():
    catalog = pp.load(reload=True)
    assert catalog.errors == {}
    assert sorted(catalog.profiles) == sorted(f.stem for f in FILES)


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_the_head_names_the_schema_the_docs_and_the_three_first_edit_failures(path):
    text = path.read_text(encoding="utf-8")
    assert text.splitlines()[0] == "#:schema ./schema.json"
    head = "\n".join(line for line in text.splitlines() if line.startswith("#"))
    for needed in ("docs/llm.md", "schema.json", "provider_profiles.local/", "id is not its file name",
                   "[env]", "implicit", "custom.toml", "atlas provider profile init"):
        assert needed in head, needed


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_every_key_is_explained(path):
    for i, line, lines in _key_lines(path.read_text(encoding="utf-8")):
        assert lines[i - 1].lstrip().startswith("#") or _trailing_comment(line), (path.name, line)


def test_no_profile_note_names_atlas_code():
    code = re.compile(r"\.py\b|(?<![\w/.])(?:core|agent|dashboard|tools)/|SetupChoice")
    for profile in pp.load(reload=True).profiles.values():
        for text in (profile.notes, profile.description, profile.label):
            assert not code.search(text), (profile.id, text)
