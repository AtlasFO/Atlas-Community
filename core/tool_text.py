"""The text a tool is sent with: its description under the provider bound
and its parameter lines as parameter descriptions (read by the toolbox and
by the registry's readers-by-format block)."""
from __future__ import annotations

import re


# A function description longer than this is cut by providers that hold
# the OpenAI limit; parameter descriptions have no such bound.
DESCRIPTION_CHARS = 1024
_PARAM_LINE_RE = re.compile(
    r"^\s*`{0,2}([A-Za-z_]\w*(?:`{0,2}\s*(?:/|,|and|or)\s*`{0,2}[A-Za-z_]\w*)*)`{0,2}\s*(?:\([^)]*\))?\s*:\s*(.*)$")


def model_description(description: str, schema: dict | None) -> tuple[str, dict]:
    """The description and parameter schema a tool is sent with
    (ATLAS_TOOL_PARAM_DESCRIPTIONS): each docstring line that documents a
    parameter ("name: text", "a / b: text", with its continuation lines up
    to a blank line or the next parameter) moves into that parameter's
    description, and the rest is the tool's description, cut at the last
    paragraph or sentence that fits the provider bound rather than in
    mid-word. Off: a plain cut at the bound."""
    from core.envfile import env_flag
    schema = dict(schema or {})
    schema.setdefault("type", "object")
    text = description or ""
    if not env_flag("ATLAS_TOOL_PARAM_DESCRIPTIONS", True):
        return text[:DESCRIPTION_CHARS], schema
    props = {k: dict(v) if isinstance(v, dict) else v for k, v in (schema.get("properties") or {}).items()}
    kept: list[str] = []
    moved: dict[str, list[str]] = {}
    current: list[str] = []
    for line in text.split("\n"):
        m = _PARAM_LINE_RE.match(line)
        names = [n for n in re.findall(r"[A-Za-z_]\w*", m.group(1)) if n not in ("and", "or")] if m else []
        if names and all(n in props for n in names):
            current = names
            for n in names:
                moved.setdefault(n, []).append(m.group(2).strip())
            continue
        if current and line.strip():
            for n in current:
                moved[n].append(line.strip())
            continue
        current = []
        kept.append(line)
    for name, parts in moved.items():
        if isinstance(props.get(name), dict):
            own = str(props[name].get("description") or "")
            props[name]["description"] = " ".join(p for p in [own, *parts] if p)
    if props:
        schema["properties"] = props
    body = re.sub(r"\n{3,}", "\n\n", "\n".join(kept)).strip()
    if len(body) > DESCRIPTION_CHARS:
        head = body[:DESCRIPTION_CHARS]
        cut = head.rfind("\n\n")
        if cut < DESCRIPTION_CHARS // 2:
            cut = max(head.rfind(". "), head.rfind(".\n"))
            cut = cut + 1 if cut > 0 else DESCRIPTION_CHARS
        body = head[:cut].rstrip()
    return body, schema
