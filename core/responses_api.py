"""OpenAI Responses API mapping — used only when a provider opts in.

Atlas's agent loop, LLM-check, WAF handling, and session restore all speak
Chat Completions ``messages``. This module translates that internal shape
to/from ``POST /v1/responses`` so the rest of the system does not change.

Default transport remains Chat Completions. Nothing here auto-selects
Responses from a model id (GPT-5, o-series, …) or from "OpenAI-compatible".
"""
from __future__ import annotations

import json
from typing import Any


def tools_to_responses(tools: list | None) -> list[dict]:
    """Flatten Chat Completions tool schemas to internally tagged functions.

    Responses wants ``{type, name, description, parameters}`` rather than
    ``{type, function: {name, …}}``. ``strict`` is set false so Atlas's
    existing tool JSON Schemas (often missing additionalProperties/required)
    are not rejected.
    """
    out: list[dict] = []
    for t in tools or []:
        if not isinstance(t, dict):
            continue
        if t.get("type") == "function" and isinstance(t.get("function"), dict):
            fn = t["function"]
            out.append({
                "type": "function",
                "name": fn.get("name") or "",
                "description": fn.get("description") or "",
                "parameters": fn.get("parameters")
                or {"type": "object", "properties": {}},
                "strict": False,
            })
            continue
        if t.get("type") == "function" and t.get("name"):
            item = {
                "type": "function",
                "name": t.get("name") or "",
                "description": t.get("description") or "",
                "parameters": t.get("parameters")
                or {"type": "object", "properties": {}},
                "strict": False,
            }
            out.append(item)
    return out


def _assistant_items_from_message(msg: dict) -> list[dict]:
    """Replay a stored Responses output array, or synthesize from Completions."""
    stored = msg.get("_responses_items")
    if isinstance(stored, list) and stored:
        return [item for item in stored if isinstance(item, dict)]
    items: list[dict] = []
    content = msg.get("content") or ""
    if content:
        items.append({"role": "assistant", "content": content})
    for tc in msg.get("tool_calls") or []:
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function") or {}
        args = fn.get("arguments")
        if not isinstance(args, str):
            try:
                args = json.dumps(args or {}, ensure_ascii=False)
            except (TypeError, ValueError):
                args = "{}"
        items.append({
            "type": "function_call",
            "call_id": tc.get("id") or "",
            "name": fn.get("name") or "",
            "arguments": args,
        })
    return items


def messages_to_responses_input(
    messages: list[dict] | None,
) -> tuple[str, list[dict]]:
    """Split Atlas Completions messages into ``instructions`` + ``input``.

    System (and developer) turns become top-level ``instructions`` — the
    Responses equivalent of a system prompt, resent every request because
    we keep ``store: false`` and do not use ``previous_response_id``.
    """
    instructions_parts: list[str] = []
    items: list[dict] = []
    for msg in messages or []:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role") or ""
        if role in ("system", "developer"):
            text = str(msg.get("content") or "")
            if text:
                instructions_parts.append(text)
            continue
        if role == "user":
            items.append({"role": "user", "content": msg.get("content") or ""})
            continue
        if role == "assistant":
            items.extend(_assistant_items_from_message(msg))
            continue
        if role == "tool":
            items.append({
                "type": "function_call_output",
                "call_id": msg.get("tool_call_id") or "",
                "output": str(msg.get("content") or ""),
            })
    return "\n\n".join(instructions_parts), items


def build_responses_payload(
    *,
    model: str,
    messages: list[dict],
    max_tokens: int | None = None,
    temperature: float | None = 0.2,
    tools: list[dict] | None = None,
    send_temperature: bool = True,
    reasoning_effort: str | None = None,
) -> dict:
    """Build a ``POST /v1/responses`` body. Conversation stays client-side.

    ``reasoning_effort`` is the same per-role level the Chat Completions body
    carries as a flat field; this API spells it ``reasoning: {effort: ...}``.
    Without this the level a user configured was silently dropped for every
    provider on this API, which is the one place the setting could be set and
    have no effect at all. "none" is not a level here: it exists on Completions
    only, to let a reasoning model call function tools, and that restriction
    does not apply to this API."""
    instructions, input_items = messages_to_responses_input(messages)
    payload: dict[str, Any] = {
        "model": model,
        "input": input_items,
        "store": False,
    }
    if max_tokens is not None:
        payload["max_output_tokens"] = int(max_tokens)
    if instructions:
        payload["instructions"] = instructions
    level = str(reasoning_effort or "").strip().lower()
    if level and level not in ("default", "none"):
        payload["reasoning"] = {"effort": level}
    if send_temperature and temperature is not None:
        payload["temperature"] = temperature
    if tools:
        payload["tools"] = tools_to_responses(tools)
        payload["tool_choice"] = "auto"
    return payload


def _parse_args(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            return {"_malformed_arguments": raw}
        return parsed if isinstance(parsed, dict) else (
            {"_malformed_arguments": raw})
    return {}


def _output_text(item: dict) -> str:
    content = item.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for part in content:
        if isinstance(part, str):
            parts.append(part)
            continue
        if not isinstance(part, dict):
            continue
        if part.get("type") in ("output_text", "text"):
            parts.append(str(part.get("text") or ""))
    return "".join(parts)


def parse_responses_body(body: dict) -> dict:
    """Normalise a Responses JSON body to fields ``parse_response`` understands.

    Returns a dict with: content, tool_calls (list of {id,name,arguments}),
    finish_reason, input_tokens, output_tokens, responses_items, raw_message.
    """
    if not isinstance(body, dict):
        raise ValueError("responses body is not an object")
    if isinstance(body.get("choices"), list):
        raise ValueError("chat_completion_shape")
    output = body.get("output")
    if not isinstance(output, list):
        output = []

    text_parts: list[str] = []
    tool_calls: list[dict] = []
    thoughts: list[str] = []
    for item in output:
        if not isinstance(item, dict):
            continue
        kind = item.get("type") or ""
        if kind == "reasoning":
            # The model's thinking, as the summaries this API exposes. Kept
            # apart from the answer, like every other dialect's thinking.
            for summary in item.get("summary") or []:
                if isinstance(summary, dict) and isinstance(summary.get("text"), str):
                    thoughts.append(summary["text"])
            continue
        if kind == "message":
            text_parts.append(_output_text(item))
        elif kind == "function_call":
            call_id = item.get("call_id") or item.get("id") or (
                f"call_{len(tool_calls)}")
            tool_calls.append({
                "id": call_id,
                "name": item.get("name") or "",
                "arguments": _parse_args(item.get("arguments")),
            })
        elif kind in ("output_text",):
            text_parts.append(str(item.get("text") or ""))

    status = (body.get("status") or "").strip().lower()
    if tool_calls:
        finish = "tool_calls"
    elif status == "incomplete":
        finish = "length"
    elif status in ("failed", "cancelled"):
        finish = status
    else:
        finish = "stop"

    usage = body.get("usage") if isinstance(body.get("usage"), dict) else {}
    return {
        "content": "".join(text_parts),
        "tool_calls": tool_calls,
        "finish_reason": finish,
        "input_tokens": int(
            usage.get("input_tokens") or usage.get("prompt_tokens") or 0),
        "output_tokens": int(
            usage.get("output_tokens") or usage.get("completion_tokens") or 0),
        "reasoning": "\n".join(t.strip() for t in thoughts if t.strip()),
        "reasoning_tokens": int(
            ((usage.get("output_tokens_details") or {}).get("reasoning_tokens")
             if isinstance(usage.get("output_tokens_details"), dict) else 0) or 0),
        "responses_items": output,
        "raw_message": {"role": "assistant", "content": "".join(text_parts)},
        "status": status,
        "response_id": body.get("id") or "",
        "error": body.get("error"),
    }
