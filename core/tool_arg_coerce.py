"""Coerce LLM tool arguments to match JSON-schema types before MCP validate.

Models (esp. tool-callers that prefer native JSON) often send:
  * a JSON **array/object** where the schema declares ``string``
    (e.g. ``phase_stack`` on ``dair_assess`` — documented as a JSON string)
  * a JSON **string** where the schema declares ``array``
    (e.g. ``columns="[\\"Timestamp\\"]"``, ``input_call_ids="[1]"``)

Without coercion these fail at Pydantic validation — the tool never runs —
and can deadlock higher gates (belief-starvation latch → record_finding →
``dair_required`` because ``dair_assess`` never landed).

No per-model catalogue: decisions come only from the tool's JSON schema.
"""
from __future__ import annotations

import json
import re
from typing import Any

_JSON_LIKE_RE = re.compile(r"^\s*[\[{]")


def _schema_types(prop: dict[str, Any]) -> set[str]:
    """Normalize a property schema's type set (handles anyOf/oneOf/type list)."""
    if not isinstance(prop, dict):
        return set()
    types: set[str] = set()
    t = prop.get("type")
    if isinstance(t, str):
        types.add(t)
    elif isinstance(t, list):
        types.update(x for x in t if isinstance(x, str))
    for key in ("anyOf", "oneOf"):
        alts = prop.get(key)
        if isinstance(alts, list):
            for alt in alts:
                types |= _schema_types(alt if isinstance(alt, dict) else {})
    return types


def _items_type(prop: dict[str, Any]) -> str | None:
    items = prop.get("items") if isinstance(prop, dict) else None
    if not isinstance(items, dict):
        return None
    t = items.get("type")
    return t if isinstance(t, str) else None


def _try_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:
        return None


def _enum_of(prop: dict[str, Any]) -> list[str]:
    """The string values a property allows (anyOf/oneOf included)."""
    if not isinstance(prop, dict):
        return []
    out = [v for v in prop.get("enum") or [] if isinstance(v, str)]
    for key in ("anyOf", "oneOf"):
        for alt in prop.get(key) or []:
            out += _enum_of(alt if isinstance(alt, dict) else {})
    return out


def _enum_spelling(value: str, allowed: list[str]) -> str | None:
    """The allowed value a spelling variant stands for: the same words in
    another case, or with spaces or hyphens for the underscores."""
    key = re.sub(r"[\s\-]+", "_", value.strip()).casefold()
    return next((a for a in allowed if a.casefold() == key), None)


def coerce_value(value: Any, prop: dict[str, Any]) -> Any:
    """Return ``value`` coerced toward ``prop``'s declared JSON-schema type."""
    allowed = _enum_of(prop)
    if allowed and isinstance(value, str) and value not in allowed:
        hit = _enum_spelling(value, allowed)
        if hit is not None:
            return hit
    types = _schema_types(prop)
    if not types:
        return value

    # Native array/object → schema string (JSON encoding).
    if "string" in types and "array" not in types and "object" not in types:
        if isinstance(value, (list, dict)):
            try:
                return json.dumps(value, ensure_ascii=False)
            except Exception:
                return value
        return value

    # Stringified JSON → schema array/object.
    if isinstance(value, str) and _JSON_LIKE_RE.match(value):
        if "array" in types or "object" in types:
            parsed = _try_json_loads(value)
            if "array" in types and isinstance(parsed, list):
                return _coerce_array_items(parsed, prop)
            if "object" in types and isinstance(parsed, dict):
                return _coerce_object_props(parsed, prop)
            # Single-quoted pseudo-JSON from some models — last resort.
            if "array" in types and value.strip().startswith("["):
                repaired = value.replace("'", '"')
                parsed = _try_json_loads(repaired)
                if isinstance(parsed, list):
                    return _coerce_array_items(parsed, prop)

    if isinstance(value, list) and "array" in types:
        return _coerce_array_items(value, prop)
    if isinstance(value, dict) and "object" in types:
        return _coerce_object_props(value, prop)

    return value


def _coerce_object_props(value: dict, prop: dict[str, Any]) -> dict:
    """An object's declared properties coerced by type (coerce_value), one
    level down and on: never a key renamed, added or dropped (the guessed-
    name rename and the underscore drop are the top-level call's alone)."""
    props = prop.get("properties") if isinstance(prop, dict) else None
    if not isinstance(value, dict) or not isinstance(props, dict):
        return value
    out = None
    for key, sub in props.items():
        if key in value and isinstance(sub, dict):
            new = coerce_value(value[key], sub)
            if (new is value[key] and isinstance(new, str) and "array" in _schema_types(sub)
                    and "string" not in _schema_types(sub) and _items_type(sub) == "string"
                    and new.strip() and not _JSON_LIKE_RE.match(new)):
                # One plain value where a list of strings is declared is a list
                # of that one value (nested only: the top level keeps its own
                # rules), never its characters.
                new = [new]
            if new is not value[key]:
                out = out if out is not None else dict(value)
                out[key] = new
    return out if out is not None else value


def _coerce_array_items(values: list, prop: dict[str, Any]) -> list:
    item_t = _items_type(prop)
    items = prop.get("items") if isinstance(prop, dict) else None
    if item_t == "object" and isinstance(items, dict) and isinstance(items.get("properties"), dict):
        coerced = [_coerce_object_props(v, items) if isinstance(v, dict) else v for v in values]
        return coerced if any(a is not b for a, b in zip(coerced, values)) else values
    if item_t not in ("integer", "number"):
        return values
    out: list = []
    changed = False
    for v in values:
        if isinstance(v, bool):
            out.append(v)
            continue
        if isinstance(v, int) and item_t == "integer":
            out.append(v)
            continue
        if isinstance(v, float) and item_t == "number":
            out.append(v)
            continue
        if isinstance(v, (int, float)) and item_t == "integer":
            out.append(int(v))
            changed = True
            continue
        if isinstance(v, str) and v.strip().lstrip("-").isdigit():
            try:
                out.append(int(v.strip()) if item_t == "integer" else float(v))
                changed = True
                continue
            except ValueError:
                pass
        out.append(v)
    return out if changed else values


_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")


def _name_words(name: str) -> set[str]:
    """The words of a parameter name: split on underscores and camel-case
    boundaries, lower-cased, a plural s dropped (``paths`` and ``path``
    are one word)."""
    parts = _CAMEL_RE.sub(r"\1_\2", name or "").lower().split("_")
    return {p[:-1] if len(p) > 3 and p.endswith("s") else p for p in parts if p}


def coerce_tool_arguments(
    arguments: dict[str, Any] | None,
    schema: dict[str, Any] | None,
) -> tuple[dict[str, Any], list[str]]:
    """Coerce ``arguments`` in place-friendly copy; return (args, notes)."""
    args = dict(arguments or {})
    if not isinstance(schema, dict):
        return args, []
    props = schema.get("properties")
    if not isinstance(props, dict):
        return args, []
    notes: list[str] = []
    # One unknown keyword and one missing required parameter of a type the
    # value fits, whose names share a word, is a guessed name, not a
    # different call: tools name the same thing path, file_path or
    # evidence_path, and a model that guesses wrong lost a whole turn to the
    # refusal. The rename is reported so the real name is learned. Names
    # that share no word (dir for image) ask for different things: renaming
    # one into the other hands the tool a value it cannot use and the model
    # a misleading error about that value, while the refusal that lists the
    # parameters is the one it corrects at once.
    required = [k for k in (schema.get("required") or [])
                if isinstance(k, str) and k in props and k not in args]
    unknown = [k for k in args if k not in props and k != "_malformed_arguments"]
    # A keyword the tool does not take whose name starts with an underscore
    # is an annotation written into the call (a note, a rationale), not an
    # argument: it is dropped and reported, and the call runs.
    for key in [k for k in unknown if k.startswith("_")]:
        args.pop(key)
        notes.append(f"{key} dropped (not a parameter of this tool)")
    unknown = [k for k in unknown if not k.startswith("_")]
    if len(required) == 1 and len(unknown) == 1:
        target, given = required[0], unknown[0]
        value = args[given]
        declared = _schema_types(props[target]) if isinstance(props[target], dict) else set()
        fits = bool(_name_words(given) & _name_words(target)) and (
                not declared
                or (isinstance(value, str) and "string" in declared)
                or (isinstance(value, bool) and "boolean" in declared)
                or (isinstance(value, int) and not isinstance(value, bool)
                    and declared & {"integer", "number"})
                or (isinstance(value, float) and "number" in declared)
                or (isinstance(value, list) and "array" in declared)
                or (isinstance(value, dict) and "object" in declared))
        if fits:
            args[target] = args.pop(given)
            notes.append(f"{given} renamed to {target} (the parameter this tool takes)")
    for key, prop in props.items():
        if key not in args or not isinstance(prop, dict):
            continue
        before = args[key]
        after = coerce_value(before, prop)
        if after is before:
            continue
        args[key] = after
        notes.append(
            f"{key}: {type(before).__name__}→{type(after).__name__}"
        )
    return args, notes
