"""The Anthropic Messages dialect, as format mapping only.

A request is built in the chat-completions shape every role already speaks
and translated here just before it goes on the wire; Messages events and
bodies come back out as the chat shapes the transport reads
(agent.llm.assemble_stream, parse_response). Everything else stays the one
transport: retries, deadlines, the stream guards, the 400 adaptation (it
runs on the chat-shaped request; ``canonical_error`` maps wire names back),
the wire dump, the ledger. Framing stays ``iter_lines`` and ``data:``; an
event's object carries its type, so ``event:`` lines are skipped.

Cache breakpoints, three of the four allowed, as 5-minute entries (the
default TTL): the last system block; the last block of the first user
message unless it is the last message; the last block before the trailing
run of user-text messages, so the per-turn steering after it stays outside
the cached prefix and its stub next turn sits after the entry. Render order
is tools, system, messages: the first breakpoint caches the tools too.

Only the leading system messages become the top-level ``system``; a system
message later in the history is sent as user text, never hoisted, so the
cached prefix does not move.

Thinking is not replayed. Validation accepts a history without thinking
blocks in adaptive mode, while the docs call replay within a tool turn
required for reasoning continuity; Atlas edits its history in place (nudge
stubs, compaction), which makes replayed thinking a 400 on accounts the
history-editing check enforces. Replay needs an append-only history first.
"""
from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from typing import Any

CACHE_ENTRY = {"type": "ephemeral"}   # 5 minutes, the default TTL
# Every documented stop reason, as the transport's finish reasons. A reply
# the context window ended is no cut at the completion limit: neither the
# loop's cut-off ask (more input) nor the thinking ladder answers it.
CONTEXT_FULL = "context_window_exceeded"
STOP = {"end_turn": "stop", "stop_sequence": "stop", "tool_use": "tool_calls",
        "max_tokens": "length", "model_context_window_exceeded": CONTEXT_FULL,
        "pause_turn": "pause", "refusal": "refusal"}
_TOOL_CHOICE = {"auto": "auto", "required": "any", "none": "none"}


# ── request ──────────────────────────────────────────────────────────────

def _text_blocks(content: Any) -> list[dict]:
    """Text blocks for a message's content; whitespace-only text is no block
    (an assistant's blank line before its tool calls)."""
    parts = [content] if isinstance(content, str) else (content or [])
    texts = [p if isinstance(p, str) else p.get("text") if isinstance(p, dict) else None for p in parts]
    return [{"type": "text", "text": t} for t in texts if isinstance(t, str) and t.strip()]


def _arguments(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw) if isinstance(raw, str) and raw.strip() else {}
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def to_wire(payload: dict, default_cap: int) -> dict:
    """The Messages request for a chat-completions ``payload``."""
    messages = list(payload.get("messages") or [])
    lead = 0
    system: list[dict] = []
    while lead < len(messages) and messages[lead].get("role") == "system":
        system += _text_blocks(messages[lead].get("content"))
        lead += 1
    turns: list[dict] = []
    last_block: dict[int, tuple[int, int]] = {}   # history index -> (turn, block) of its last block
    for i in range(lead, len(messages)):
        msg = messages[i]
        role = msg.get("role")
        if role == "assistant":
            blocks = _text_blocks(msg.get("content"))
            for call in msg.get("tool_calls") or []:
                fn = call.get("function") or {}
                blocks.append({"type": "tool_use", "id": str(call.get("id") or ""),
                               "name": str(fn.get("name") or ""), "input": _arguments(fn.get("arguments"))})
            wire_role = "assistant"
        elif role == "tool":
            blocks = [{"type": "tool_result", "tool_use_id": str(msg.get("tool_call_id") or ""),
                       "content": str(msg.get("content") or "")}]
            wire_role = "user"
        else:
            blocks, wire_role = _text_blocks(msg.get("content")), "user"
        if not blocks:
            continue
        if turns and turns[-1]["role"] == wire_role:
            turns[-1]["content"].extend(blocks)
        else:
            turns.append({"role": wire_role, "content": blocks})
        last_block[i] = (len(turns) - 1, len(turns[-1]["content"]) - 1)
    _mark(system, turns, messages, lead, last_block)
    body: dict = {"model": payload.get("model"),
                  "max_tokens": int(payload.get("max_tokens") or payload.get("max_completion_tokens")
                                    or default_cap)}
    if system:
        body["system"] = system
    body["messages"] = turns
    if payload.get("tools"):
        body["tools"] = [{"name": (t.get("function") or {}).get("name"),
                          "description": (t.get("function") or {}).get("description") or "",
                          "input_schema": (t.get("function") or {}).get("parameters")
                          or {"type": "object", "properties": {}}}
                         for t in payload["tools"]]
        choice = _TOOL_CHOICE.get(str(payload.get("tool_choice") or "auto"))
        if choice:
            body["tool_choice"] = {"type": choice}
    if payload.get("reasoning_effort"):
        body["output_config"] = {"effort": payload["reasoning_effort"]}
    if "temperature" in payload:
        body["temperature"] = payload["temperature"]
    if payload.get("stream"):
        body["stream"] = True
    return body


def _mark(system: list[dict], turns: list[dict], messages: list[dict], lead: int,
          last_block: dict[int, tuple[int, int]]) -> None:
    """Put the three breakpoints on copies of their blocks."""
    def mark(where: tuple[int, int] | None) -> None:
        if where is not None:
            turn, block = where
            turns[turn]["content"][block] = {**turns[turn]["content"][block], "cache_control": CACHE_ENTRY}
    if system:
        system[-1] = {**system[-1], "cache_control": CACHE_ENTRY}
    first_user = next((i for i in range(lead, len(messages)) if messages[i].get("role") == "user"
                       and i in last_block), None)
    if first_user is not None and first_user < len(messages) - 1:
        mark(last_block[first_user])
    tail = len(messages)     # a late system message goes out as user text: part of the run
    while tail > lead and messages[tail - 1].get("role") in ("user", "system"):
        tail -= 1
    before = next((i for i in range(tail - 1, lead - 1, -1) if i in last_block), None)
    if before is not None and first_user is not None and before > first_user:
        mark(last_block[before])


# ── reply ────────────────────────────────────────────────────────────────

def chat_usage(usage: dict) -> dict:
    """Messages usage as the chat usage block the ledger reads: the prompt is
    uncached + written + read, the cached share is what was read."""
    read = int(usage.get("cache_read_input_tokens") or 0)
    write = int(usage.get("cache_creation_input_tokens") or 0)
    out: dict = {"prompt_tokens": int(usage.get("input_tokens") or 0) + write + read,
                 "completion_tokens": int(usage.get("output_tokens") or 0),
                 "prompt_tokens_details": {"cached_tokens": read},
                 "cache_creation_input_tokens": write}
    thinking = (usage.get("output_tokens_details") or {}).get("thinking_tokens")
    if thinking:
        out["completion_tokens_details"] = {"reasoning_tokens": int(thinking)}
    return out


def _refusal(details: Any) -> dict:
    details = details if isinstance(details, dict) else {}
    return {"category": details.get("category"), "explanation": details.get("explanation")}


def _line(obj: dict) -> str:
    return "data: " + json.dumps(obj, ensure_ascii=False)


def chunks(lines: Iterable) -> Iterator[str]:
    """Messages stream events as chat chunk lines for assemble_stream.
    Unknown event types are skipped, as the versioning policy asks."""
    usage: dict = {}
    slots: dict[int, int] = {}       # content block index -> tool call index
    for raw in lines:
        line = (raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)).strip()
        if line.startswith(":"):
            yield line
            continue
        if not line.startswith("data:"):
            continue
        try:
            event = json.loads(line[5:].strip())
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        kind = event.get("type")
        if kind == "ping":
            yield ": ping"
        elif kind == "error":
            yield _line({"error": event.get("error") or {"message": "error event"}})
        elif kind == "message_start":
            message = event.get("message") or {}
            usage.update({k: v for k, v in (message.get("usage") or {}).items() if v is not None})
            yield _line({"id": message.get("id"), "model": message.get("model"), "choices": []})
        elif kind == "content_block_start":
            block = event.get("content_block") or {}
            if block.get("type") == "tool_use":
                slot = slots[int(event.get("index") or 0)] = len(slots)
                yield _line({"choices": [{"index": 0, "delta": {"tool_calls": [{
                    "index": slot, "id": block.get("id"), "type": "function",
                    "function": {"name": block.get("name"), "arguments": ""}}]}}]})
            elif block.get("type") == "text" and block.get("text"):
                yield _line({"choices": [{"index": 0, "delta": {"content": block["text"]}}]})
        elif kind == "content_block_delta":
            delta = event.get("delta") or {}
            if delta.get("type") == "text_delta":
                yield _line({"choices": [{"index": 0, "delta": {"content": delta.get("text") or ""}}]})
            elif delta.get("type") == "thinking_delta":
                yield _line({"choices": [{"index": 0, "delta": {"reasoning_content": delta.get("thinking") or ""}}]})
            elif delta.get("type") == "input_json_delta":
                slot = slots.get(int(event.get("index") or 0))
                if slot is not None:
                    yield _line({"choices": [{"index": 0, "delta": {"tool_calls": [{
                        "index": slot, "function": {"arguments": delta.get("partial_json") or ""}}]}}]})
        elif kind == "message_delta":
            usage.update({k: v for k, v in (event.get("usage") or {}).items() if v is not None})
            delta = event.get("delta") or {}
            stop = delta.get("stop_reason")
            if stop:
                chunk: dict = {"choices": [{"index": 0, "delta": {}, "finish_reason": STOP.get(stop, stop)}]}
                if stop == "refusal":
                    chunk["atlas_refusal"] = _refusal(delta.get("stop_details") or event.get("stop_details"))
                yield _line(chunk)
        elif kind == "message_stop":
            yield _line({"choices": [], "usage": chat_usage(usage)})
            yield "data: [DONE]"


def to_chat_body(body: dict) -> dict:
    """A non-streamed Messages body as the chat body parse_response reads."""
    if not isinstance(body, dict) or body.get("type") != "message":
        return body
    text, thinking, calls = [], [], []
    for block in body.get("content") or []:
        kind = block.get("type") if isinstance(block, dict) else None
        if kind == "text":
            text.append(str(block.get("text") or ""))
        elif kind == "thinking":
            thinking.append(str(block.get("thinking") or ""))
        elif kind == "tool_use":
            calls.append({"id": block.get("id"), "type": "function",
                          "function": {"name": block.get("name"),
                                       "arguments": json.dumps(block.get("input") or {}, ensure_ascii=False)}})
    message: dict = {"role": "assistant", "content": "".join(text)}
    if any(t for t in thinking):
        message["reasoning_content"] = "\n".join(t for t in thinking if t)
    if calls:
        message["tool_calls"] = calls
    stop = body.get("stop_reason") or ""
    out = {"id": body.get("id"), "model": body.get("model"), "object": "chat.completion",
           "choices": [{"index": 0, "message": message, "finish_reason": STOP.get(stop, stop)}],
           "usage": chat_usage(body.get("usage") or {})}
    if stop == "refusal":
        out["atlas_refusal"] = _refusal(body.get("stop_details"))
    return out


def canonical_error(text: str) -> str:
    """A 400 body with the wire's names for the chat-shaped request's: the
    effort lives in reasoning_effort there."""
    return (text or "").replace("output_config.effort", "reasoning_effort").replace(
        "output_config", "reasoning_effort")
