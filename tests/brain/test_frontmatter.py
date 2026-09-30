from core.brain import frontmatter


def test_parse_roundtrip():
    meta = {"title": "T", "type": "note", "created": "2026-07-07",
            "updated": "2026-07-07", "status": "active",
            "source_classification": "internal", "confidence": "high",
            "tags": ["a"], "source": {"type": "manual"}}
    text = frontmatter.serialize(meta, "# T\n\nbody")
    parsed, body, warnings = frontmatter.parse(text)
    assert parsed["title"] == "T"
    assert "body" in body
    assert warnings == []


def test_parse_missing_frontmatter():
    meta, body, warnings = frontmatter.parse("# just markdown")
    assert meta == {}
    assert "missing frontmatter" in warnings


def test_parse_missing_fields_warn():
    meta, _, warnings = frontmatter.parse("---\ntitle: X\n---\nbody")
    assert meta["title"] == "X"
    assert any("missing type" in w for w in warnings)


def test_parse_invalid_yaml_never_raises():
    meta, _, warnings = frontmatter.parse("---\n{unclosed: [\n---\nbody")
    assert meta == {}
    assert any("invalid YAML" in w for w in warnings)


def test_parse_body_with_hr():
    text = "---\ntitle: X\n---\nintro\n\n---\n\noutro"
    meta, body, _ = frontmatter.parse(text)
    assert meta["title"] == "X"
    assert "outro" in body
