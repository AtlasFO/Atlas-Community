"""Tolerant YAML frontmatter parsing/serialization for brain notes."""

from __future__ import annotations

import yaml

REQUIRED_FIELDS = ("title", "type", "created", "updated", "status",
                   "source_classification", "confidence", "tags", "source")


def parse(text: str) -> tuple[dict, str, list[str]]:
    """Split a Markdown document into (frontmatter dict, body, warnings).

    Never raises on malformed input: returns an empty dict plus warnings so
    indexing can report quality issues instead of crashing.
    """
    warnings: list[str] = []
    if not text.startswith("---"):
        return {}, text, ["missing frontmatter"]
    parts = text.split("\n---", 2)
    if len(parts) < 2:
        return {}, text, ["unterminated frontmatter"]
    raw = parts[0][3:]
    body = parts[1] if len(parts) == 2 else parts[1] + "\n---" + parts[2]
    # Body starts right after the closing fence; strip one leading newline.
    body = body[1:] if body.startswith("\n") else body
    try:
        meta = yaml.safe_load(raw) or {}
    except yaml.YAMLError as e:
        return {}, text, [f"invalid YAML frontmatter: {e.__class__.__name__}"]
    if not isinstance(meta, dict):
        return {}, body, ["frontmatter is not a mapping"]
    for field in REQUIRED_FIELDS:
        if field not in meta:
            warnings.append(f"missing {field}")
    return meta, body, warnings


def serialize(meta: dict, body: str) -> str:
    fm = yaml.safe_dump(meta, sort_keys=False, allow_unicode=True,
                        default_flow_style=None).rstrip()
    return f"---\n{fm}\n---\n\n{body.lstrip()}"
