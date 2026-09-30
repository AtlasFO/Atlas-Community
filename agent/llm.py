"""OpenAI-compatible chat client for Atlas.

Primary target is the **T-Systems LLM Hub** (``LLMHUB_*`` / provider
``llmhub``, default model GLM — classic ``max_tokens`` + ``temperature``).
Named alternate providers (e.g. a direct vendor endpoint next to the hub)
use the same client; per-provider+model API quirks are learned from HTTP
400s and cached under ``~/.atlas/llm_api_compat.json``.

Deliberately httpx-based (already a Atlas dependency) rather than the openai
SDK: Atlas needs tolerant response parsing (`reasoning_content`, string tool
arguments, missing usage blocks) across whatever model the hub serves.
"""
from __future__ import annotations

import json
import os
import re
import time
from collections import deque
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import httpx

from core import llmhub, providers

RETRYABLE_STATUS = {408, 409, 500, 502, 503, 504}
MAX_RETRIES = 4
# 429s (rate limits) are budgeted by total wait time rather than attempts:
# the hub's TPM window needs up to a minute to drain, so a handful of short
# exponential backoffs is never enough.
RATE_LIMIT_WAIT_BUDGET = float(
    os.environ.get("ATLAS_AGENT_RATE_LIMIT_WAIT") or "600")
# Ceiling on ONE request with its retries, backoff and 429 waits (each
# starvation-ladder rung sends its own request and gets its own budget).
# Without it the worst case is ~3000s (4 × (600s timeout + backoff) + 600s
# rate budget) — a single wedged request can otherwise freeze the Report
# phase for hours. When the budget runs out chat raises LLMDeadlineError,
# which the agent loop routes to a graceful wrap-up instead of a crash.
# A streamed reply is bounded inside the request by REPLY_SHARE of the
# budget, and a cut the client makes is re-asked once, so one chat() call
# spends at most about one budget on a reply that does not converge.
# 0 disables.
TURN_TIME_BUDGET_DEFAULT = 1800.0
# The share of the budget one streamed reply may take before it is cut;
# the rest is the re-ask's. At the default budget that is 900 s, above the
# longest reply a role completes on the hubs measured; the budget is the
# knob when a hub is slower.
REPLY_SHARE = 0.5
# Proactive pacing: keep our own input-token spend under the hub's per-model
# TPM cap so we rarely trip 429 at all. 0 disables.
_INPUT_TPM_DEFAULT = 400_000  # under a provider's per-model input cap, with margin

_RETRY_HINT = re.compile(r"try again in ([0-9]+(?:\.[0-9]+)?) seconds?", re.I)

# Parse OpenAI-compatible / gateway 400 bodies across providers.
_UNSUPPORTED_PARAM_RE = re.compile(
    r"(?i)(?:unsupported parameter|unknown parameter|"
    r"unrecognized request argument(?:\s+supplied)?|"
    r"invalid parameter|"
    r"does not support(?:\s+the)?\s+parameter|"
    r"parameter\s+is\s+not\s+supported)\s*[:=]?\s*['\"]?([A-Za-z_][\w]*)['\"]?"
)
_USE_INSTEAD_RE = re.compile(
    r"(?i)use\s+['\"]?([A-Za-z_][\w]*)['\"]?\s+instead"
)
# Soft first-guess only — never authoritative; learned cache wins.
# Do NOT soft-hint the hub's catalogue models (GLM / Llama / …).
_SOFT_MAX_COMPLETION_RE = re.compile(
    r"(?i)(?:^|[/_.-])(?:gpt-5(?:\.\d+)?|o[1-9]|o[34](?:-mini)?)(?:$|[/_.-])"
)
# Narrower than the above: only GPT-5.x is documented to reject Completions
# tool-calling without reasoning_effort=none (GPT-5.4+). Older o-series
# (o1/o3/o4-mini) keep the max_completion_tokens hint above but are left to
# the reactive 400-adapter for this field, since "none" is not confirmed
# valid for them and a wrong proactive guess would fail their first request.
_SOFT_REASONING_EFFORT_RE = re.compile(r"(?i)(?:^|[/_.-])gpt-5(?:\.\d+)?(?:$|[/_.-])")
# A firewall's 403 names itself: "Web Application Firewall", or a product
# name ending in WAF ("AWS WAF", "ExampleWAF"). Anchored on both sides, so a
# request id or a word that merely contains the letters ("wafer") is not one.
_WAF_NOTICE_RE = re.compile(
    r"(?i)web application firewall|(?<![a-z0-9])[a-z]*waf(?![a-z0-9])")
_HUB_CLASSIC_MODEL_RE = re.compile(
    r"(?i)(?:^|[/_.-])(?:glm|llama|qwen|mixtral|mistral|deepseek|phi|"
    r"command-r|yi-|internlm|solar)(?:$|[/_.\d-])"
)

_COMPAT_SCHEMA = 1
_MAX_ADAPT_ROUNDS = 4

# How an endpoint takes a thinking level. Every vendor's OpenAI-compatible
# endpoint spells it one of these ways; the preset says which, a 400 can
# correct it, and the payload builder is the only place that knows the
# spelling.
THINKING_REASONING_EFFORT = "reasoning_effort"   # OpenAI, hubs, Gemini, xAI, Mistral, Ollama
THINKING_REASONING_OBJECT = "reasoning_object"   # OpenRouter: reasoning: {effort}
THINKING_TYPE = "thinking_type"                  # Z.ai, DeepSeek: thinking: {type}
THINKING_ENABLE = "enable_thinking"              # DashScope: enable_thinking
THINKING_BUDGET = "thinking_budget"              # Anthropic compat: thinking: {budget_tokens}
THINKING_NONE = "none"                           # the model has no such control
THINKING_CONTROLS = (THINKING_REASONING_EFFORT, THINKING_REASONING_OBJECT,
                     THINKING_TYPE, THINKING_ENABLE, THINKING_BUDGET, THINKING_NONE)

# Levels the starvation ladder steps through, most thinking first, so a
# climb settles at the most thinking that still answers. "medium" is
# skipped because it is the default on most endpoints and unbounded on
# others; "none" is never sent by the ladder because a model that cannot
# stop thinking answers it by writing the thinking into the answer.
LADDER_LEVELS = ("high", "low", "minimal")

# Explicit completion ceiling used only when an endpoint has shown it needs
# one: its own default cut a reply short, or it refuses a request whose cap
# sits below its thinking budget. A ceiling, not a target.
EXPLICIT_CAP = 65536

# Anthropic-style budgets for a level, when the control is a budget.
_BUDGET_BY_LEVEL = {"minimal": 1024, "low": 2048, "medium": 8192,
                    "high": 16384, "xhigh": 32768, "max": 32768}


@dataclass
class ApiCompatProfile:
    """How to shape chat-completions JSON for one provider+model pair.

    Defaults are classic OpenAI-compatible (works for most hubs/providers).
    Profiles come from a preset, are refined from HTTP 400s and from what
    replies show, and are persisted so model switches only pay the
    adaptation cost once.
    """
    completion_limit: str = "max_tokens"  # or max_completion_tokens
    send_temperature: bool = True
    drop_params: tuple[str, ...] = ()
    # Completions-only: send reasoning_effort=none with Atlas function tools
    # so GPT-5.4+ does not 400. None means omit the field.
    reasoning_effort: str | None = None
    # How this endpoint takes a thinking level, and which values it listed as
    # accepted (empty means not yet known).
    thinking_control: str = THINKING_REASONING_EFFORT
    effort_values: tuple[str, ...] = ()
    # Message fields the endpoint wants back in the history on later turns
    # (DeepSeek direct: reasoning_content; OpenRouter Anthropic: reasoning_details).
    echo_fields: tuple[str, ...] = ()
    # The endpoint's own completion default cut a reply short, or it refused
    # a cap below its thinking budget: send EXPLICIT_CAP from now on.
    needs_explicit_cap: bool = False
    # A reply from this model carried thinking text or a reasoning count.
    reasoning_observed: bool = False
    # The level the ladder found answering, per role, after the endpoint's
    # own starvation at the level above: the climb is paid once per install
    # rather than on every call. A rescue after a cut the client itself
    # made is not kept; it proves nothing about the level.
    level_by_role: dict = field(default_factory=dict)
    # How many tool schemas this model answered with a function call after
    # a larger list came back without one. None means never seen to fail.
    max_tools: int | None = None
    source: str = "default"  # default | soft | learned | env

    def to_dict(self) -> dict:
        data = {
            "completion_limit": self.completion_limit,
            "send_temperature": self.send_temperature,
            "drop_params": list(self.drop_params),
            "source": self.source,
        }
        if self.reasoning_effort:
            data["reasoning_effort"] = self.reasoning_effort
        if self.thinking_control != THINKING_REASONING_EFFORT:
            data["thinking_control"] = self.thinking_control
        if self.effort_values:
            data["effort_values"] = list(self.effort_values)
        if self.echo_fields:
            data["echo_fields"] = list(self.echo_fields)
        if self.needs_explicit_cap:
            data["needs_explicit_cap"] = True
        if self.reasoning_observed:
            data["reasoning_observed"] = True
        if self.level_by_role:
            data["level_by_role"] = dict(self.level_by_role)
        if self.max_tools:
            data["max_tools"] = int(self.max_tools)
        return data

    @classmethod
    def from_dict(cls, data: dict | None) -> "ApiCompatProfile":
        data = data or {}
        limit = data.get("completion_limit") or "max_tokens"
        if limit not in ("max_tokens", "max_completion_tokens"):
            limit = "max_tokens"

        def _strings(key: str) -> tuple[str, ...]:
            raw = data.get(key) or []
            if not isinstance(raw, (list, tuple)):
                return ()
            return tuple(str(x) for x in raw if isinstance(x, str))

        effort = data.get("reasoning_effort")
        if str(effort or "").strip().lower() != "none":
            effort = None
        else:
            effort = "none"
        control = str(data.get("thinking_control") or THINKING_REASONING_EFFORT)
        if control not in THINKING_CONTROLS:
            control = THINKING_REASONING_EFFORT
        by_role = data.get("level_by_role")
        by_role = ({k: v for k, v in by_role.items()
                    if isinstance(k, str) and isinstance(v, str) and v}
                   if isinstance(by_role, dict) else {})
        max_tools = data.get("max_tools")
        max_tools = (int(max_tools)
                     if isinstance(max_tools, int) and max_tools > 0 else None)
        return cls(
            completion_limit=limit,
            send_temperature=bool(data.get("send_temperature", True)),
            drop_params=_strings("drop_params"),
            reasoning_effort=effort,
            thinking_control=control,
            effort_values=_strings("effort_values"),
            echo_fields=_strings("echo_fields"),
            needs_explicit_cap=bool(data.get("needs_explicit_cap", False)),
            reasoning_observed=bool(data.get("reasoning_observed", False)),
            level_by_role=by_role,
            max_tools=max_tools,
            source=str(data.get("source") or "learned"),
        )


def _compat_cache_path() -> Path:
    override = (os.environ.get("ATLAS_LLM_COMPAT_CACHE") or "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".atlas" / "llm_api_compat.json"


def _compat_key(provider: str, model: str) -> str:
    return f"{(provider or 'default').strip().lower()}|{(model or '').strip()}"


_compat_mem: dict[str, ApiCompatProfile] = {}
_compat_loaded = False
# Keys this process changed and has not written yet. The file is shared by
# every Atlas process on the host (runs, the dashboard, the CLI), so a save
# writes only these over what is on disk, never the whole memory.
_compat_dirty: set[str] = set()


def _load_compat_cache() -> None:
    global _compat_loaded
    if _compat_loaded:
        return
    _compat_loaded = True
    path = _compat_cache_path()
    try:
        if not path.is_file():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        models = (data or {}).get("models") or {}
        if isinstance(models, dict):
            for k, v in models.items():
                if isinstance(k, str) and isinstance(v, dict):
                    _compat_mem[k] = ApiCompatProfile.from_dict(v)
    except Exception:
        pass


def _save_compat_cache() -> None:
    """Write the keys this process changed over the file as it is now.

    Another process may have learned something since this one read the
    file; its entries stay. A file this process cannot read is not one it
    overwrites: the change is kept in memory and tried again next time.
    """
    path = _compat_cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        on_disk: dict = {}
        if path.is_file():
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                on_disk = (raw or {}).get("models") or {}
            except (OSError, ValueError):
                return
        models = {k: v for k, v in on_disk.items()
                  if isinstance(k, str) and isinstance(v, dict)}
        for key in list(_compat_dirty):
            if key in _compat_mem:
                models[key] = _compat_mem[key].to_dict()
        payload = {
            "schema_version": _COMPAT_SCHEMA,
            "models": {k: models[k] for k in sorted(models)},
        }
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp, path)
        _compat_dirty.clear()
    except OSError:
        pass


def remember_api_compat(
    provider: str,
    model: str,
    profile: ApiCompatProfile,
    *,
    persist: bool = True,
) -> None:
    """Store a working profile for provider+model (process + optional disk)."""
    _load_compat_cache()
    key = _compat_key(provider, model)
    stored = replace(profile, drop_params=tuple(profile.drop_params),
                     level_by_role=dict(profile.level_by_role),
                     source="learned")
    _compat_mem[key] = stored
    _compat_dirty.add(key)
    if persist:
        _save_compat_cache()


def clear_api_compat_cache(*, memory_only: bool = False) -> None:
    """Test helper / operator reset."""
    global _compat_loaded
    _compat_mem.clear()
    _compat_dirty.clear()
    _compat_loaded = True if memory_only else False
    if not memory_only:
        try:
            p = _compat_cache_path()
            if p.is_file():
                p.unlink()
        except OSError:
            pass


def _env_forced_profile() -> ApiCompatProfile | None:
    """Optional global overrides — for locked-down deployments."""
    limit_force = (os.environ.get("ATLAS_LLM_MAX_COMPLETION_TOKENS") or "").strip().lower()
    temp_force = (os.environ.get("ATLAS_LLM_ALLOW_TEMPERATURE") or "").strip().lower()
    if not limit_force and not temp_force:
        return None
    limit = "max_tokens"
    if limit_force in ("1", "true", "yes", "on"):
        limit = "max_completion_tokens"
    elif limit_force in ("0", "false", "no", "off"):
        limit = "max_tokens"
    else:
        limit_force = ""
    send_temp = True
    if temp_force in ("0", "false", "no", "off"):
        send_temp = False
    elif temp_force in ("1", "true", "yes", "on"):
        send_temp = True
    else:
        temp_force = ""
    if not limit_force and not temp_force:
        return None
    return ApiCompatProfile(
        completion_limit=limit if limit_force else "max_tokens",
        send_temperature=send_temp if temp_force else True,
        source="env",
    )


def _soft_bootstrap_profile(
    model: str,
    provider: str = "",
) -> ApiCompatProfile | None:
    """Cheap first-request guess. Optional; never overrides learned/env.

    the LLM hub defaults (GLM, Llama, …) stay classic OpenAI-compatible.
    Soft ``max_completion_tokens`` hints apply only to known OpenAI-family
    ids (useful when traffic goes to api.openai.com directly).
    """
    if (os.environ.get("ATLAS_LLM_COMPAT_SOFT_HINTS") or "1").strip().lower() in (
        "0", "false", "no", "off",
    ):
        return None
    name = model or ""
    # Hub catalogue families: always classic until a 400 teaches otherwise.
    if _HUB_CLASSIC_MODEL_RE.search(name):
        return None
    if _SOFT_MAX_COMPLETION_RE.search(name):
        return ApiCompatProfile(
            completion_limit="max_completion_tokens",
            send_temperature=False,
            reasoning_effort=(
                "none" if _SOFT_REASONING_EFFORT_RE.search(name) else None
            ),
            source="soft",
        )
    # Default provider llmhub with unknown id → classic (hub dialect).
    prov = (provider or "").strip().lower()
    if prov in ("", "llmhub", "default", "t-systems", "tsystems"):
        return None
    return None


def resolve_api_compat(
    provider: str,
    model: str,
) -> ApiCompatProfile:
    """Resolve how to talk to this provider+model.

    Priority: env override → learned cache (per provider|model) → soft
    bootstrap → classic default (the LLM hub dialect).
    """
    forced = _env_forced_profile()
    if forced is not None:
        # Env may only force one dimension; merge with learned when partial.
        _load_compat_cache()
        learned = _compat_mem.get(_compat_key(provider, model))
        if learned and forced.source == "env":
            # The override forces the dimensions it names; everything the
            # cache learned about this model stays, the tool ceiling and
            # the observed thinking included. Rebuilding the profile from
            # the forced fields alone dropped those, and the next store
            # persisted the loss.
            return replace(
                learned,
                completion_limit=(
                    forced.completion_limit
                    if (os.environ.get("ATLAS_LLM_MAX_COMPLETION_TOKENS") or "").strip()
                    else learned.completion_limit
                ),
                send_temperature=(
                    forced.send_temperature
                    if (os.environ.get("ATLAS_LLM_ALLOW_TEMPERATURE") or "").strip()
                    else learned.send_temperature
                ),
                source="env",
            )
        return forced

    _load_compat_cache()
    key = _compat_key(provider, model)
    if key in _compat_mem:
        return _compat_mem[key]

    soft = _soft_bootstrap_profile(model, provider=provider)
    if soft is not None:
        return soft
    preset = _preset_profile(provider)
    if preset is not None:
        return preset
    return ApiCompatProfile(source="default")


def _preset_profile(provider: str) -> ApiCompatProfile | None:
    """The request shape a provider's preset declares, when it declares one.

    A provider registered from a vendor preset records the preset id in
    ``ATLAS_PROVIDER_<NAME>_PRESET``; a provider named after a preset
    ("openrouter", "deepseek") counts as that preset. Nothing learned yet
    starts from here instead of from the classic default.
    """
    name = (provider or "").strip()
    if not name:
        return None
    from core import llm_setup
    preset_id = (os.environ.get(providers.var(name, "PRESET")) or "").strip() or name
    fields = llm_setup.preset_profile(preset_id)
    if not fields:
        return None
    return ApiCompatProfile(source="preset", **fields)


def _embedded_json(text: str) -> dict | None:
    """The JSON object a gateway embedded as text in its own error string
    (the hub's ``detail`` reads "Error: 400 - Bad Request - {…}", LiteLLM's
    message reads "AnthropicException - {…}")."""
    start = text.find("{")
    if start < 0:
        return None
    try:
        data = json.loads(text[start:])
    except (json.JSONDecodeError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def normalize_error_body(body_text: str, _depth: int = 0) -> str:
    """Flatten provider JSON errors (OpenAI ``error.message``, hub ``detail``),
    including one wrapped as text inside another."""
    text = body_text or ""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return text
    if not isinstance(data, dict):
        return text
    parts: list[str] = []
    err = data.get("error")
    if isinstance(err, dict):
        for k in ("message", "param", "code", "type"):
            v = err.get(k)
            if v:
                parts.append(str(v))
    elif isinstance(err, str):
        parts.append(err)
    for k in ("detail", "message", "msg", "error_description"):
        v = data.get(k)
        if isinstance(v, str) and v.strip():
            parts.append(v)
        elif isinstance(v, list):
            parts.extend(str(x) for x in v)
    if _depth < 2:
        for part in list(parts):
            inner = _embedded_json(part)
            if inner is not None:
                parts.append(normalize_error_body(json.dumps(inner), _depth + 1))
    flat = " ".join(parts).strip()
    return f"{flat}\n{text}" if flat else text


def profile_from_payload(
    payload: dict, *, source: str = "learned",
    drop_params: tuple[str, ...] = (),
    base: ApiCompatProfile | None = None,
) -> ApiCompatProfile:
    """Infer a profile from a payload that the API accepted (or was adapted to).

    `drop_params` names params this round's 400-adaptation removed for a
    reason `payload`'s own shape can't reconstruct (e.g. a provider
    rejecting `tool_choice` outright) — build_chat_payload always adds them
    back next turn otherwise, so the same 400 recurs every turn. `base`
    carries the fields a payload's shape says nothing about (how thinking is
    controlled, what was observed) so a learned profile does not forget them.
    """
    if "max_completion_tokens" in payload:
        limit = "max_completion_tokens"
    elif "max_tokens" in payload or base is None:
        limit = "max_tokens"
    else:
        limit = base.completion_limit
    effort = payload.get("reasoning_effort")
    if str(effort or "").strip().lower() != "none":
        effort = None
    else:
        effort = "none"
    sends_temperature = "temperature" in payload
    if base is not None and "temperature" not in payload and base.send_temperature:
        # A payload built without a temperature says nothing about whether
        # the endpoint takes one; only a payload the adapter stripped it
        # from does, and that path passes the stripped payload here.
        sends_temperature = base.send_temperature
    return replace(
        base or ApiCompatProfile(),
        completion_limit=limit,
        send_temperature=sends_temperature,
        drop_params=tuple(drop_params),
        reasoning_effort=effort,
        source=source,
    )


def apply_thinking_level(payload: dict, control: str, level: str | None) -> None:
    """Put ``level`` on ``payload`` the way ``control`` spells it. Empty and
    "default" send nothing: the endpoint's own level, chosen on purpose."""
    value = str(level or "").strip().lower()
    if not value or value == "default":
        return
    if control == THINKING_REASONING_EFFORT:
        payload["reasoning_effort"] = value
    elif control == THINKING_REASONING_OBJECT:
        payload["reasoning"] = {"effort": value}
    elif control == THINKING_TYPE:
        if value == "none":
            payload["thinking"] = {"type": "disabled"}
        else:
            payload["thinking"] = {"type": "enabled"}
            payload["reasoning_effort"] = value
    elif control == THINKING_ENABLE:
        payload["enable_thinking"] = value != "none"
    elif control == THINKING_BUDGET:
        if value == "none":
            payload["thinking"] = {"type": "disabled"}
        else:
            payload["thinking"] = {"type": "enabled",
                                   "budget_tokens": _BUDGET_BY_LEVEL.get(value, 8192)}


def build_chat_payload(
    *,
    model: str,
    messages: list[dict],
    max_tokens: int | None = None,
    temperature: float | None = 0.2,
    tools: list[dict] | None = None,
    provider: str = "",
    profile: ApiCompatProfile | None = None,
    thinking_level: str | None = None,
    response_format: dict | None = None,
    tool_choice: str | None = None,
) -> dict:
    """Build a chat-completions body using the resolved API compat profile.

    No completion limit is sent unless ``max_tokens`` is given: a thinking
    model pays its thinking out of that limit, and every fixed cap Atlas
    used to send starved one on the hub. ``thinking_level`` is spelled the
    way the profile's control says; a profile that pins ``reasoning_effort``
    to "none" for function tools keeps that pin on tool turns, because the
    endpoint required it.
    """
    prof = profile or resolve_api_compat(provider, model)
    payload: dict = {
        "model": model,
        "messages": messages,
    }
    if max_tokens is not None:
        limit_key = prof.completion_limit
        if limit_key not in ("max_tokens", "max_completion_tokens"):
            limit_key = "max_tokens"
        payload[limit_key] = int(max_tokens)
    if prof.send_temperature and temperature is not None:
        payload["temperature"] = float(temperature)
    if response_format:
        payload["response_format"] = response_format
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = tool_choice or "auto"
    if tools and prof.reasoning_effort:
        payload["reasoning_effort"] = prof.reasoning_effort
    else:
        apply_thinking_level(payload, prof.thinking_control, thinking_level)
    for name in prof.drop_params:
        payload.pop(name, None)
    mark_cache_breakpoints(payload, model, provider)
    return payload


def mark_cache_breakpoints(payload: dict, model: str, provider: str = "") -> dict:
    """Anthropic models cache only what is explicitly marked: the system
    frame (playbook and tool schemas, the largest stable block) and the
    case brief get ``cache_control`` breakpoints. Providers with implicit
    prefix caching (OpenAI, OpenRouter's Z.AI/DeepSeek routes) need nothing
    but a stable prefix, so the payload is left as it is."""
    m = (model or "").lower()
    if not (m.startswith("anthropic/") or m.startswith("claude") or provider == "anthropic"):
        return payload
    marked = 0
    for msg in payload.get("messages") or []:
        if marked >= 2:
            break
        if msg.get("role") not in ("system", "user"):
            continue
        content = msg.get("content")
        if isinstance(content, str) and content.strip():
            msg["content"] = [{"type": "text", "text": content,
                               "cache_control": {"type": "ephemeral"}}]
            marked += 1
        elif isinstance(content, list) and content and isinstance(content[-1], dict):
            content[-1].setdefault("cache_control", {"type": "ephemeral"})
            marked += 1
    return payload


# Back-compat helpers used by older tests / callers
def uses_max_completion_tokens(model: str, provider: str = "") -> bool:
    return resolve_api_compat(provider, model).completion_limit == (
        "max_completion_tokens"
    )


def supports_temperature(model: str, provider: str = "") -> bool:
    return resolve_api_compat(provider, model).send_temperature


def _current_level(payload: dict) -> str | None:
    """The thinking level a payload carries, whichever spelling."""
    if isinstance(payload.get("reasoning_effort"), str):
        return payload["reasoning_effort"]
    reasoning = payload.get("reasoning")
    if isinstance(reasoning, dict) and isinstance(reasoning.get("effort"), str):
        return reasoning["effort"]
    return None


def _set_level(payload: dict, level: str) -> None:
    if isinstance(payload.get("reasoning"), dict):
        payload["reasoning"] = {**payload["reasoning"], "effort": level}
    else:
        payload["reasoning_effort"] = level


def adapt_payload_for_400(
    payload: dict,
    body_text: str,
    *,
    prior_drop_params: tuple[str, ...] = (),
    profile: ApiCompatProfile | None = None,
) -> tuple[dict, ApiCompatProfile] | None:
    """Adapt payload from a provider 400. Returns (new_payload, profile) or None.

    Provider-agnostic: works for T-Systems LLM Hub ``detail`` bodies and
    OpenAI-style ``error.message`` bodies. Renames known limit fields, drops
    unsupported params named in the error, steps a refused thinking level to
    one the body lists as accepted, raises a cap the body says is below the
    thinking budget, and learns a durable profile.

    `prior_drop_params` carries forward params an EARLIER 400-round already
    learned to drop for this same request (e.g. one round drops
    "tool_choice", a later round drops "top_p" too) — without merging, each
    round's profile_from_payload() would only see the params dropped in
    *that* round and forget the rest.
    """
    text = normalize_error_body(body_text)
    text_l = text.lower()
    out = dict(payload)
    changed = False
    dropped: list[str] = list(prior_drop_params)
    base = profile or ApiCompatProfile()

    # A body that lists the values the option takes: step to one of them
    # rather than losing the option. Never "none"; see LADDER_LEVELS.
    handled: set[str] = set()
    accepted = accepted_values_from_error(text)
    current = _current_level(out)
    if accepted and current is not None and current not in accepted:
        for candidate in (*LADDER_LEVELS, "medium", "xhigh", "max"):
            if candidate in accepted:
                _set_level(out, candidate)
                changed = True
                handled.add("reasoning_effort")
                break
        base = replace(base, effort_values=tuple(accepted))

    # An option named in the body as unsupported, in whatever wording the
    # gateway uses ("response_format is not supported"): drop it and
    # remember, so the next request does not pay the same refusal.
    for key in ("response_format", "tool_choice", "reasoning_effort"):
        if key in out and key not in handled and key in text_l and any(
                s in text_l for s in ("not supported", "unsupported",
                                      "invalid", "unknown", "unrecognized")):
            out.pop(key, None)
            changed = True
            if key not in dropped:
                dropped.append(key)

    # "Reasoning is mandatory and cannot be disabled": the only value that
    # asks for that is "none", so ask for the least thinking instead.
    if current == "none" and "cannot be disabled" in text_l:
        _set_level(out, "low")
        base = replace(base, reasoning_effort=None)
        changed = True

    # A cap below the endpoint's thinking budget (Anthropic through LiteLLM):
    # the answer is a cap large enough, remembered for this model.
    if "budget_tokens" in text_l and "max_tokens" in text_l:
        limit_key = "max_completion_tokens" if "max_completion_tokens" in out else "max_tokens"
        if int(out.get(limit_key) or 0) < EXPLICIT_CAP:
            out[limit_key] = EXPLICIT_CAP
            base = replace(base, needs_explicit_cap=True)
            changed = True

    # Explicit rename hints (OpenAI GPT-5 style).
    if "max_tokens" in out and "max_completion_tokens" not in out:
        if (
            "max_completion_tokens" in text_l
            and ("max_tokens" in text_l)
            and any(
                s in text_l
                for s in ("not supported", "unsupported", "use ", "instead")
            )
        ):
            out["max_completion_tokens"] = out.pop("max_tokens")
            changed = True
    if "max_tokens" in out and "max_output_tokens" not in out:
        if "max_output_tokens" in text_l and "max_tokens" in text_l:
            out["max_output_tokens"] = out.pop("max_tokens")
            changed = True
    if "max_completion_tokens" in out and "max_tokens" not in out:
        if (
            "max_tokens" in text_l
            and "max_completion_tokens" in text_l
            and "not supported" in text_l
            and "use" in text_l
            and "max_tokens" in text_l
        ):
            # Rare reverse: gateway wants classic max_tokens
            instead = _USE_INSTEAD_RE.search(text)
            if instead and instead.group(1) == "max_tokens":
                out["max_tokens"] = out.pop("max_completion_tokens")
                changed = True

    # Generic "unsupported parameter: X" / "use Y instead"
    for m in _UNSUPPORTED_PARAM_RE.finditer(text):
        bad = m.group(1)
        if bad not in out:
            continue
        instead = None
        window = text[m.start(): m.start() + 160]
        im = _USE_INSTEAD_RE.search(window) or _USE_INSTEAD_RE.search(text)
        if im:
            instead = im.group(1)
        if instead and instead != bad:
            out[instead] = out.pop(bad)
            changed = True
        else:
            out.pop(bad, None)
            changed = True
            # A true drop with no replacement (e.g. "unsupported parameter:
            # tool_choice") isn't reconstructable from `out`'s shape the way
            # completion_limit/reasoning_effort/temperature are below — it
            # must be tracked explicitly or build_chat_payload adds it right
            # back next turn and the same 400 recurs forever.
            if bad not in dropped:
                dropped.append(bad)

    # Temperature / sampling knobs often rejected without a clean param name.
    if "temperature" in out and any(
        s in text_l
        for s in (
            "temperature",
            "sampling",
            "does not support temperature",
        )
    ) and any(
        s in text_l
        for s in ("not supported", "unsupported", "invalid", "cannot")
    ):
        out.pop("temperature", None)
        changed = True

    # GPT-5.4+ Completions rejects Atlas function tools while the model
    # reasons (default effort is not none). Stay on Completions: send
    # reasoning_effort=none so the existing Atlas tool loop keeps working.
    # OpenAI hosted tools are not used.
    if out.get("tools") and "reasoning_effort" in text_l:
        if any(
            s in text_l
            for s in ("function tool", "function tools", "tool calling")
        ) and any(
            s in text_l
            for s in (
                "not supported",
                "unsupported",
                "/v1/responses",
                "set reasoning_effort",
            )
        ):
            if out.get("reasoning_effort") != "none":
                out["reasoning_effort"] = "none"
                changed = True

    if not changed:
        return None

    # Extra safety: never send both limit fields
    if "max_tokens" in out and "max_completion_tokens" in out:
        if "max_completion_tokens" in text_l and "use" in text_l:
            out.pop("max_tokens", None)
        else:
            out.pop("max_completion_tokens", None)

    learned = profile_from_payload(
        out, source="learned", drop_params=tuple(dropped), base=base)
    if "temperature" in payload and "temperature" not in out:
        learned = replace(learned, send_temperature=False)
    return out, learned


# Alias kept for older call sites / tests
def _adapt_payload_for_400(payload: dict, body_text: str) -> dict | None:
    result = adapt_payload_for_400(payload, body_text)
    return None if result is None else result[0]


def rate_limit_delay(body_text: str, headers: dict, attempt: int) -> float:
    """Best wait before retrying a 429/retryable response.

    Prefers a Retry-After header, then the LLM Hub's own hint in the body
    ('Please try again in 33.30 seconds.'), then exponential backoff.
    """
    retry_after = (headers.get("retry-after") or "").strip()
    if retry_after.replace(".", "", 1).isdigit():
        return min(float(retry_after) + 1.0, 120.0)
    m = _RETRY_HINT.search(body_text or "")
    if m:
        return min(float(m.group(1)) + 2.0, 120.0)
    return min(2 ** attempt * 2, 30)


class LLMError(RuntimeError):
    pass


class LLMDeadlineError(LLMError):
    """The per-turn time budget (ATLAS_AGENT_TURN_TIME_BUDGET) ran out before
    the hub returned a response. Retryable in principle — the agent loop
    treats it as "this turn is lost, wrap up or move on", never as a fatal
    run error."""


class LLMTransportError(LLMError):
    """The provider could not be reached or dropped the reply on every
    attempt one request makes (connection errors, a reply cut off mid-body,
    retryable statuses). A later request may well succeed, so the agent loop
    asks the turn again after a pause; a 4xx, an auth or a WAF refusal is not
    this error and repeats identically."""


class WAFBlockedError(LLMError):
    """A gateway's web application firewall rejected the request (HTTP 418,
    or 403 with a firewall notice).

    Forensic content routinely contains attack-like strings (injected
    commands, LFI-style paths, shellcode fragments) that such firewalls
    flag. The agent loop reacts by dropping the offending tool
    output from context — it never tries to disguise content to slip it past
    the WAF.
    """


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict


@dataclass
class ChatResponse:
    """One model reply, the same shape whatever served it.

    ``content`` is the answer and the only field the pipeline reads.
    ``reasoning`` is the model's thinking when the provider returned it in a
    field of its own; it is kept for the trace and never promoted into the
    answer. ``raw_message`` is the provider's message as sent, so a profile
    that must echo provider fields back (thinking blocks, reasoning details)
    can copy them from there.
    """
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    # Input tokens the provider served from its prompt cache (billed at a
    # fraction of the price). OpenAI-compatible bodies report it under
    # usage.prompt_tokens_details.cached_tokens, Anthropic-style ones as
    # usage.cache_read_input_tokens.
    cached_tokens: int = 0
    reasoning: str = ""
    reasoning_tokens: int = 0
    # False when the body carried no usage block: a reply the client cut
    # before the usage chunk, or an endpoint that drops stream_options. The
    # counts are then zero and the ledger says so instead of pricing them.
    usage_reported: bool = False
    raw_message: dict = field(default_factory=dict)
    responses_items: list = field(default_factory=list)
    # Raw names of function calls the loop could not name a tool from
    # (empty, or no tool name at all) and dropped before the history.
    malformed_calls: list = field(default_factory=list)
    # Why a streamed reply reads as cut: "stream_end" when the connection
    # ended before the reply finished, "thinking_bound" when the client
    # closed it for thinking that ran past the role's own record,
    # "deadline" when it ran past the reply's share of the time budget,
    # "degenerate" when its text repeated with a short period (that text
    # is dropped). Empty for a reply the provider finished itself.
    cut_reason: str = ""

    @property
    def thinking_observed(self) -> bool:
        """The reply shows the model thought: thinking text, or a count of
        hidden reasoning tokens. Either alone is proof; one gateway reports a
        zero count beside the text, another the text with no count."""
        return bool(self.reasoning) or self.reasoning_tokens > 0

    @property
    def starved(self) -> bool:
        """No answer and no tool call although the model spent its budget on
        thinking: cut off at the completion limit, or the reasoning count
        accounts for the whole completion."""
        if self.content or self.tool_calls:
            return False
        if self.finish_reason == "length":
            return True
        return (self.reasoning_tokens > 0
                and self.reasoning_tokens >= max(self.output_tokens - 1, 1))

    def starved_reason(self) -> str:
        """Human-readable account of an empty reply, for errors and traces."""
        fr = self.finish_reason or "unknown"
        if self.starved:
            return (
                "Model returned empty response: completion budget exhausted by "
                f"hidden reasoning tokens (finish_reason={fr}, "
                f"reasoning_tokens={self.reasoning_tokens}, "
                f"completion_tokens={self.output_tokens}).")
        return (
            f"Model returned empty response (finish_reason={fr}, "
            f"reasoning_tokens={self.reasoning_tokens}, "
            f"completion_tokens={self.output_tokens}).")


# Calls made through this client. Efforts are configured per role
# (ATLAS_EFFORT_AGENT), so the analyst can be tuned without moving the
# roles that reason on its behalf.
_AGENT_ROLE = "agent"

# The shapes a Chat Completions reply arrives in differ by serving stack, not
# by vendor: one gateway can answer in a different shape for each model behind
# it. Every shape below has a hand-written fixture under tests/fixtures/llm/;
# a new one is added there first, then here.
_THINK_OPEN = "<think>"
_THINK_CLOSE = "</think>"


def _split_leading_think(text: str) -> tuple[str, str]:
    """(thinking, remainder) for a think block at the very start of ``text``.

    A server without a reasoning parser leaves the model's own block in the
    content: ``<think>…</think>answer``. A chat template that opens the block
    itself leaves only the closing tag: ``…</think>answer``. Both are known
    structures and are split; a tag anywhere else is content and is kept,
    because nothing is removed on a guess.
    """
    stripped = text.lstrip()
    close = stripped.find(_THINK_CLOSE)
    if close < 0:
        return "", text
    head = stripped[:close]
    if head.startswith(_THINK_OPEN):
        head = head[len(_THINK_OPEN):]
    elif _THINK_OPEN in head:
        return "", text
    return head.strip(), stripped[close + len(_THINK_CLOSE):]


def _text_of_parts(parts: list) -> tuple[str, str]:
    """(content, thinking) from a content list: text parts make the answer,
    ``thinking`` parts (Mistral's chunk shape) make the thinking."""
    texts: list[str] = []
    thoughts: list[str] = []
    for part in parts:
        if isinstance(part, str):
            texts.append(part)
            continue
        if not isinstance(part, dict):
            continue
        kind = part.get("type") or ""
        if kind == "thinking":
            inner = part.get("thinking")
            if isinstance(inner, str):
                thoughts.append(inner)
            elif isinstance(inner, list):
                thoughts.extend(str(p.get("text") or "") for p in inner
                                if isinstance(p, dict))
            continue
        if isinstance(part.get("text"), str):
            texts.append(part["text"])
    return "".join(texts), "\n".join(t for t in thoughts if t.strip()).strip()


def _first_text(items: Any, key: str) -> str:
    """Joined non-empty ``key`` strings of a list of objects, or ""."""
    if not isinstance(items, list):
        return ""
    found = [str(it[key]).strip() for it in items
             if isinstance(it, dict) and isinstance(it.get(key), str)
             and it[key].strip()]
    return "\n".join(found)


def reasoning_tokens_from_usage(usage: Any) -> int:
    """Hidden-thinking count wherever the gateway put it: OpenAI nests it
    under completion_tokens_details, sglang puts it straight on usage, others
    send none."""
    if not isinstance(usage, dict):
        return 0
    details = usage.get("completion_tokens_details")
    value = details.get("reasoning_tokens") if isinstance(details, dict) else None
    if value is None:
        value = usage.get("reasoning_tokens")
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _parse_tool_calls(raw: Any) -> list[ToolCall]:
    calls: list[ToolCall] = []
    for tc in raw or []:
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function") if isinstance(tc.get("function"), dict) else tc
        args = fn.get("arguments")
        if isinstance(args, str):
            try:
                args = json.loads(args) if args.strip() else {}
            except json.JSONDecodeError:
                # Hand malformed JSON back to the model as a tool error later
                # rather than crashing the loop. Only the head is kept: the
                # arguments go back into the history as the call the model
                # made, and one that ran to hundreds of kilobytes made every
                # later request carry it.
                args = malformed_arguments(args)
        if not isinstance(args, dict):
            args = {}
        calls.append(ToolCall(
            id=str(tc.get("id") or f"call_{len(calls)}"),
            name=str(fn.get("name") or ""),
            arguments=args,
        ))
    return calls



_wire_seq = 0


def _wire_dump(payload: dict) -> Path | None:
    """Write the request to ``ATLAS_LLM_WIRE_DIR`` and return the file stem
    the reply is written next to; None when the variable is unset. A run
    whose replies come back in a shape the loop cannot use is read from
    these files, the request and the raw stream side by side."""
    global _wire_seq
    where = (os.environ.get("ATLAS_LLM_WIRE_DIR") or "").strip()
    if not where:
        return None
    _wire_seq += 1
    root = Path(where)
    root.mkdir(parents=True, exist_ok=True)
    stem = root / f"{time.strftime('%H%M%S')}_{os.getpid()}_{_wire_seq:04d}"
    stem.with_suffix(".request.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=1, default=str),
        encoding="utf-8")
    return stem


def _tee_lines(lines, path: Path):
    """Yield the stream's lines unchanged while writing them to ``path``."""
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(str(line) + "\n")
            yield line

class _FoldedReply:
    """A streamed reply, read the way the request path reads a plain one."""

    def __init__(self, status_code: int, headers, body: dict):
        self.status_code = status_code
        self.headers = headers
        self._body = body
        self.text = json.dumps(body)[:2000]

    def json(self) -> dict:
        return self._body


def assemble_stream(lines, *, reasoning_limit: int = 0,
                    deadline: float | None = None) -> dict:
    """Fold a Chat Completions event stream into the body one reply carries.

    ``reasoning_limit`` is the most thinking, in characters, the reply may
    accumulate before any answer text or call has begun; past it the stream
    is closed and the reply reads as cut (see REASONING_RUNAWAY_FACTOR).
    ``deadline`` is a ``time.monotonic()`` value past which the stream is
    closed whatever arrives, keepalives included: with no output begun the
    reply reads as cut and empty, with output begun as cut at an output
    limit with the head of its content. A stream whose recent text repeats
    with a short period (see REPEAT_WINDOW_CHARS) is closed as degenerate
    and the repeated text is dropped. A call slot a cut left without
    arguments is dropped with it, so no tool runs on arguments it never had.

    Text, thinking and tool-call arguments arrive as deltas; each is
    appended to its slot (tool calls by index), the finish reason and the
    usage block come from the chunks that carry them, and ``[DONE]`` ends
    it. The result goes through ``parse_response`` like any other body.

    A stream that ends with neither a finish reason nor ``[DONE]`` was cut
    off, by the gateway or the network, and what arrived is not the reply:
    it raises as a transport error so the request is made again, instead
    of an empty or half-written reply reaching the loop.
    """
    message: dict = {"role": "assistant", "content": "", "reasoning_content": ""}
    calls: dict[int, dict] = {}
    finish = ""
    usage: dict = {}
    meta: dict = {}
    done = False
    runaway = False
    cut = ""
    for raw in lines:
        if deadline is not None and time.monotonic() > deadline:
            cut = "deadline"
            break
        line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
        line = line.strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            done = True
            break
        try:
            chunk = json.loads(data)
        except ValueError:
            continue
        if not isinstance(chunk, dict):
            continue
        for key in ("id", "model"):
            if chunk.get(key):
                meta[key] = chunk[key]
        if isinstance(chunk.get("usage"), dict) and chunk["usage"]:
            usage = chunk["usage"]
        for choice in chunk.get("choices") or []:
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta") or {}
            if isinstance(delta.get("content"), str):
                message["content"] += delta["content"]
            for key in ("reasoning_content", "reasoning"):
                if isinstance(delta.get(key), str):
                    message["reasoning_content"] += delta[key]
            for tc in delta.get("tool_calls") or []:
                if not isinstance(tc, dict):
                    continue
                try:
                    index = int(tc.get("index") or 0)
                except (TypeError, ValueError):
                    index = 0
                slot = calls.setdefault(index, {
                    "id": "", "type": "function",
                    "function": {"name": "", "arguments": ""}})
                if tc.get("id"):
                    slot["id"] = str(tc["id"])
                fn = tc.get("function") or {}
                if fn.get("name"):
                    slot["function"]["name"] = str(fn["name"])
                if isinstance(fn.get("arguments"), str):
                    slot["function"]["arguments"] += fn["arguments"]
            if choice.get("finish_reason"):
                finish = str(choice["finish_reason"])
        if (reasoning_limit and not calls and not message["content"]
                and len(message["reasoning_content"]) > reasoning_limit):
            runaway = True
            finish = "length"
            break
        if _periodic(message["content"]) or _periodic(message["reasoning_content"]):
            cut = "degenerate"
            break
    if runaway:
        cut = "thinking_bound"
    if cut == "deadline":
        finish = "length"
        message["content"] = message["content"][:CUT_CONTENT_KEEP]
    elif cut == "degenerate":
        finish = "length"
        message["content"] = ""
        message["reasoning_content"] = ""
    elif not cut and not done and not finish:
        arrived = (len(message["content"]) + len(message["reasoning_content"])
                   + sum(len(c["function"]["arguments"]) for c in calls.values()))
        if arrived < STREAM_CUT_RETRY_CHARS:
            raise httpx.RemoteProtocolError(
                "event stream ended before the reply finished")
        # Real output arrived and then the connection ended: the reply was
        # cut, as at an output limit, and the loop treats it as one; the
        # history carries its head only.
        finish = "length"
        cut = "stream_end"
        message["content"] = message["content"][:CUT_CONTENT_KEEP]
    if cut:
        for index in [i for i, c in calls.items() if not c["function"]["arguments"].strip()]:
            del calls[index]
    if calls:
        message["tool_calls"] = [calls[i] for i in sorted(calls)]
    if not message["reasoning_content"]:
        del message["reasoning_content"]
    body = {**meta, "object": "chat.completion",
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": usage}
    if cut:
        body["atlas_cut"] = cut
    return body


# How much of a tool call's unparseable argument string is kept. The head
# is what the refusal shows the model and what the history carries; the rest
# is by definition not a call.
MALFORMED_ARGUMENTS_KEEP = 2000


def longest_argument(raw: str) -> tuple[str, int]:
    """The top-level parameter of a JSON object text whose value spans the
    most characters, with that span. The text may end anywhere: a value
    still open at the end runs to it, which is the parameter a cut reply
    was writing when it ran out. ("", 0) when no parameter can be read."""
    best = ("", 0)
    depth = 0
    in_str = esc = False
    tok = -1           # where the open string token began
    pending = None     # a string closed at depth 1, a key once ':' follows
    key, start = None, 0

    def close(end: int) -> None:
        nonlocal best, key
        size = len(raw[start:end].strip())
        if key is not None and size > best[1]:
            best = (key, size)
        key = None

    for i, ch in enumerate(raw):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
                if depth == 1 and key is None:
                    pending = raw[tok + 1:i]
            continue
        if ch == '"':
            in_str, tok = True, i
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            if depth == 1:
                close(i)
            depth -= 1
        elif ch == ":" and depth == 1 and pending is not None:
            key, start, pending = pending, i + 1, None
        elif ch == "," and depth == 1:
            close(i)
    close(len(raw))
    return best


def malformed_arguments(raw: str) -> dict:
    """The arguments of a call whose arguments were not JSON. Only the head
    is kept: the arguments go back into the history as the call the model
    made. A text cut past the head also names the parameter that took most
    of it, which is what a shorter call has to shorten."""
    if len(raw) <= MALFORMED_ARGUMENTS_KEEP:
        return {"_malformed_arguments": raw}
    args = {"_malformed_arguments":
            raw[:MALFORMED_ARGUMENTS_KEEP] + f" … [{len(raw)} characters, cut]"}
    name, size = longest_argument(raw)
    if name:
        args["_longest_argument"] = f"{name} ({size} characters)"
    return args


# A stream that ends early with less than this much output delivered no
# reply and is asked again; with more, it is a reply the connection cut,
# and a second attempt would be cut the same way.
# Note: a fixed threshold; measure the gateway's limits if it misfires.
STREAM_CUT_RETRY_CHARS = 2000

# Thinking that runs past this many times the longest thinking a role has
# completed in this run, with no answer begun, is a deliberation that is
# not converging: the stream is closed and the reply read as cut, which
# the starvation ladder answers by lowering the thinking level and asking
# again. Relative to the model's own replies, so a verbose model sets its
# own scale; nothing is bounded before a role has answered once.
REASONING_RUNAWAY_FACTOR = 3
# ... and nothing is bounded until the role's longest completed thinking is
# at least this long. A run's first replies are often trivial (a few dozen
# tokens of thinking before "start the log"), and three times a trivial
# reply is a size the model exceeds on any real step; a bound built on it
# cut every reply that thought at all. A runaway is minutes of output; a
# record shorter than this says nothing about one.
# Note: a fixed threshold; measure runaway sizes before moving it.
REASONING_RUNAWAY_FLOOR_CHARS = 32_000

# A stream whose recent text repeats with a short period is not
# converging, and that shows within minutes (a window of one-character
# tokens at a hub's pace) rather than at the deadline:
# once the content (or the thinking) holds a window of this many
# characters that equals itself shifted by some period up to
# REPEAT_MAX_PERIOD, the stream is closed as degenerate and the repeated
# text is dropped, so the reply reads as empty and a fresh request is made
# instead of the run carrying the repetition into its history.
REPEAT_WINDOW_CHARS = 4096
REPEAT_MAX_PERIOD = 32
# What a reply cut at its deadline keeps of its content: the head. The rest
# is, by the cut, what did not converge, and the history must not carry it.
CUT_CONTENT_KEEP = 4000
# The cuts the client itself makes, as opposed to a connection that ended.
CLIENT_CUTS = frozenset({"thinking_bound", "deadline", "degenerate"})


def _periodic(text: str) -> bool:
    """True when the last REPEAT_WINDOW_CHARS of ``text`` repeat with a
    period of at most REPEAT_MAX_PERIOD characters."""
    if len(text) < REPEAT_WINDOW_CHARS:
        return False
    window = text[-REPEAT_WINDOW_CHARS:]
    return any(window[p:] == window[:-p] for p in range(1, REPEAT_MAX_PERIOD + 1))


def parse_response(body: dict) -> ChatResponse:
    """Normalise a Chat Completions body from any serving stack.

    The answer comes from ``content`` only. Thinking is read from whichever
    field carried it and never promoted into the answer: a reply whose only
    text is its thinking is an empty reply, and the caller decides what an
    empty reply means.
    """
    try:
        choice = body["choices"][0]
    except (KeyError, IndexError, TypeError):
        raise LLMError(f"Malformed chat response: {json.dumps(body)[:500]}")
    message = choice.get("message") or {}

    raw_content = message.get("content")
    parts_thinking = ""
    if isinstance(raw_content, list):
        content, parts_thinking = _text_of_parts(raw_content)
    elif isinstance(raw_content, str):
        content = raw_content
    else:
        content = ""
    inline_thinking, content = _split_leading_think(content)
    content = content.strip()

    reasoning = ""
    for key in ("reasoning_content", "reasoning"):
        value = message.get(key)
        if isinstance(value, str) and value.strip():
            reasoning = value.strip()
            break
    if not reasoning:
        reasoning = (_first_text(message.get("reasoning_details"), "text")
                     or _first_text(message.get("thinking_blocks"), "thinking")
                     or parts_thinking or inline_thinking)
    if not reasoning and isinstance(message.get("thinking"), str):
        reasoning = message["thinking"].strip()

    usage = body.get("usage") or {}
    return ChatResponse(
        content=content,
        tool_calls=_parse_tool_calls(message.get("tool_calls")),
        finish_reason=choice.get("finish_reason") or "",
        input_tokens=int(usage.get("prompt_tokens") or 0),
        output_tokens=int(usage.get("completion_tokens") or 0),
        cached_tokens=cached_input_tokens(usage),
        reasoning=reasoning,
        reasoning_tokens=reasoning_tokens_from_usage(usage),
        usage_reported=bool(usage),
        raw_message=message,
        cut_reason=str(body.get("atlas_cut") or ""),
    )


# How gateways spell "these are the values this option takes" in a 400. The
# list is what the request path steps through instead of dropping the option.
_ACCEPTED_LIST_RES = (
    re.compile(r"Supported values are:\s*\[([^\]]*)\]"),
    re.compile(r"literal\[([^\]]*)\]"),
)
_QUOTED_RE = re.compile(r"'([^']+)'")


def accepted_values_from_error(text: str) -> list[str] | None:
    """The option values an error body lists as accepted, or None when the
    body names none. Reads Mistral's "Supported values are: [...]" and the
    sglang/pydantic "literal[...]" form."""
    for pattern in _ACCEPTED_LIST_RES:
        m = pattern.search(text or "")
        if m:
            values = _QUOTED_RE.findall(m.group(1))
            if values:
                return values
    return None


def cached_input_tokens(usage: dict) -> int:
    """Prompt-cache reads in a usage block, whichever dialect reported them."""
    if not isinstance(usage, dict):
        return 0
    details = usage.get("prompt_tokens_details") or {}
    for v in (details.get("cached_tokens") if isinstance(details, dict) else None,
              usage.get("cache_read_input_tokens"), usage.get("cached_tokens")):
        try:
            if v:
                return int(v)
        except (TypeError, ValueError):
            continue
    return 0


def parse_responses(body: dict) -> ChatResponse:
    """Parse a Responses API body into the same ChatResponse the agent uses."""
    from core.responses_api import parse_responses_body
    try:
        data = parse_responses_body(body)
    except (TypeError, ValueError) as exc:
        raise LLMError(
            f"Malformed responses body: {json.dumps(body)[:500]}"
        ) from exc
    if data.get("error"):
        raise LLMError(f"Responses API error: {data['error']}")
    tool_calls = [
        ToolCall(
            id=tc.get("id") or "",
            name=tc.get("name") or "",
            arguments=tc.get("arguments") or {},
        )
        for tc in data.get("tool_calls") or []
    ]
    return ChatResponse(
        content=(data.get("content") or "").strip(),
        tool_calls=tool_calls,
        finish_reason=data.get("finish_reason") or "",
        input_tokens=int(data.get("input_tokens") or 0),
        output_tokens=int(data.get("output_tokens") or 0),
        reasoning=str(data.get("reasoning") or ""),
        reasoning_tokens=int(data.get("reasoning_tokens") or 0),
        usage_reported=bool((data.get("input_tokens") or 0)
                            or (data.get("output_tokens") or 0)),
        raw_message=data.get("raw_message") or {},
        responses_items=list(data.get("responses_items") or []),
    )


class LLMHubClient:
    def __init__(self, base_url: str = "", api_key: str = "", model: str = "",
                 timeout: float = 600.0, provider: str = "",
                 auth_header: str = "", auth_prefix: str | None = None,
                 usage_provider: str = "", turn_time_budget: float | None = None):
        # Overrides are stored; unset values resolve from the environment at
        # request time, because the GNOME Keyring loader (core.secrets) may
        # only populate os.environ after this client is constructed.
        self._base_url = base_url
        self._api_key = api_key
        self._model = model
        # Empty means not configured — resolve() raises instead of using the hub.
        self._provider_name = provider
        # The provider a caller resolved its endpoint from, when it passes the
        # endpoint rather than the name: the usage ledger's label for the
        # call, and nothing else (the learned request shape stays keyed by
        # ``provider``).
        self._usage_provider = usage_provider
        # A caller that resolved its endpoint itself (the legacy REASON_* /
        # DAIR_* variables) can name the auth header it needs.
        self._auth_header = auth_header
        self._auth_prefix = auth_prefix
        self.timeout = timeout
        # A chat completion is streamed by default: the read timeout then
        # guards silence between chunks rather than the length of a reply,
        # and a gateway that cuts idle connections sees a live one. A reply
        # that takes ten minutes to write arrives; before, it was cut and
        # retried from the start until the attempts ran out.
        self.stream = (os.environ.get("ATLAS_LLM_STREAM", "1").strip().lower()
                       not in ("0", "false", "no", "off"))
        # The longest thinking each role has completed in this process, in
        # characters, and the role of the call in flight: what a streamed
        # reply's thinking is measured against.
        self._reasoning_seen: dict[str, int] = {}
        self._reasoning_role = ""
        # What the starvation ladder did on the last chat() call, for the
        # caller's trace: one entry per rung climbed.
        self.ladder_events: list[dict] = []
        # A caller whose call runs under its own deadline (a reasoning tool
        # under its watchdog) passes that deadline, so the reply cut and the
        # lower rungs of the ladder fit inside it.
        self.turn_time_budget = float(
            turn_time_budget if turn_time_budget
            else os.environ.get("ATLAS_AGENT_TURN_TIME_BUDGET") or TURN_TIME_BUDGET_DEFAULT)
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cached_tokens = 0
        self.input_tpm_budget = int(
            os.environ.get("ATLAS_AGENT_INPUT_TPM") or _INPUT_TPM_DEFAULT)
        # (timestamp, input_tokens) of requests in the trailing minute
        self._spend: deque[tuple[float, int]] = deque()

    @property
    def provider(self) -> providers.Provider:
        """Resolved every access, never cached — same reason as the properties
        below: core.secrets may fill os.environ after construction."""
        return providers.resolve(self._provider_name)

    @property
    def base_url(self) -> str:
        return (self._base_url or self.provider.base_url).rstrip("/")

    @property
    def api_key(self) -> str:
        if self._api_key:
            return self._api_key.strip()
        try:
            return (self.provider.api_key or "").strip()
        except providers.UnknownProvider:
            # An explicit endpoint with no key and no registered provider:
            # a local server. Nothing to send, nothing to resolve.
            if self._base_url:
                return ""
            raise

    @property
    def model(self) -> str:
        if self._model:
            return self._model
        provider = self.provider
        if provider.model:
            return provider.model
        # Only reachable for a named provider: the default one always yields
        # llmhub.DEFAULT_MODEL. Refusing here beats inheriting the hub's model
        # id and sending it to a catalogue that never had it.
        raise LLMError(
            f"no model configured for provider {provider.name!r}: set "
            f"{providers.var(provider.name, 'MODEL')} or pass --model")

    # ── input-TPM pacing ─────────────────────────────────────────────────

    def _pace(self, estimated_tokens: int) -> None:
        """Sleep just long enough that this request stays under the hub's
        input tokens-per-minute cap, based on our own trailing-minute spend."""
        if self.input_tpm_budget <= 0:
            return
        now = time.monotonic()
        while self._spend and now - self._spend[0][0] > 60:
            self._spend.popleft()
        spent = sum(tok for _, tok in self._spend)
        while self._spend and spent + estimated_tokens > self.input_tpm_budget:
            ts, tok = self._spend[0]
            wait = 60 - (time.monotonic() - ts)
            if wait > 0:
                time.sleep(min(wait + 0.5, 60))
            self._spend.popleft()
            spent -= tok

    def _record_spend(self, input_tokens: int) -> None:
        if self.input_tpm_budget > 0 and input_tokens:
            self._spend.append((time.monotonic(), input_tokens))

    def _provider_name_safe(self) -> str:
        try:
            return self.provider.name
        except Exception:  # noqa: BLE001 — unregistered names are still usable
            return self._provider_name or ""

    @property
    def profile(self) -> ApiCompatProfile:
        """How to shape a request for this provider+model right now."""
        return resolve_api_compat(self._provider_name_safe(), self.model)

    @property
    def echo_fields(self) -> tuple[str, ...]:
        """Message fields the endpoint wants back in the history."""
        return self.profile.echo_fields

    def learned_max_tools(self) -> int | None:
        """How many tool schemas this provider+model has shown it can take."""
        try:
            return self.profile.max_tools
        except Exception:  # noqa: BLE001 - unconfigured client: nothing learned
            return None

    def learn_max_tools(self, count: int) -> None:
        """Remember the tool list size at which this provider+model answered
        with a function call: the cut that answered after a larger list
        came back without one, or the probe past the remembered size that
        answered. The stored size moves in either direction on that
        evidence and in neither without it; ATLAS_AGENT_MAX_OPENAI_TOOLS
        bounds it from above."""
        try:
            profile = self.profile
            provider_name = self._provider_name_safe()
            model = self.model
        except Exception:  # noqa: BLE001 - nothing to attach the fact to
            return
        count = int(count)
        if count <= 0 or profile.max_tools == count:
            return
        remember_api_compat(provider_name, model,
                            replace(profile, max_tools=count))

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        key = self.api_key
        if key:
            # Bearer for the hub and every OpenAI-compatible endpoint; a
            # gateway wanting another scheme configures it per provider. A
            # client built from explicit base_url/api_key with no provider
            # name (tests, ad-hoc scripts) has nothing registered to
            # resolve — fall back to the generic default instead of
            # refusing to send a request that already has a real key.
            header, prefix = self._auth_header, self._auth_prefix
            if not header:
                try:
                    provider = self.provider
                    header = getattr(provider, "auth_header", "") or providers.DEFAULT_AUTH_HEADER
                    prefix = getattr(provider, "auth_prefix", None)
                except Exception:  # noqa: BLE001
                    header = providers.DEFAULT_AUTH_HEADER
                    prefix = None
            if prefix is None:
                prefix = providers.resolve_auth_prefix(header, None)
            headers[header] = f"{prefix}{key}"
        return headers

    def thinking_level_for(self, role: str, profile: ApiCompatProfile) -> str | None:
        """The level to ask for: a per-role override, else the provider's
        pinned level, else the level the ladder found answering for this
        role, else nothing (the endpoint's own). What the operator pinned
        is never overruled by what was learned."""
        value = llmhub.reasoning_effort_for(role) if role else None
        if value:
            return value
        name = self._provider_name_safe()
        pinned = providers.thinking_level(name) if name else ""
        if pinned:
            return pinned
        return profile.level_by_role.get(role or "") or None

    @staticmethod
    def _cap_for(max_tokens: int | None, profile: ApiCompatProfile) -> int | None:
        """The completion limit to send: what the caller asked, else the
        operator's ceiling, else an explicit cap only where the endpoint has
        shown it needs one, else nothing."""
        if max_tokens is not None:
            return int(max_tokens)
        ceiling = (os.environ.get("ATLAS_LLM_MAX_OUTPUT_TOKENS") or "").strip()
        if ceiling.isdigit() and int(ceiling) > 0:
            return int(ceiling)
        return EXPLICIT_CAP if profile.needs_explicit_cap else None

    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             *, role: str = _AGENT_ROLE, max_tokens: int | None = None,
             temperature: float | None = 0.2,
             response_format: dict | None = None,
             compact: Any = None, level: str | None = None,
             tool_choice: str | None = None) -> ChatResponse:
        """One model call for any role, over the one transport.

        ``role`` names the caller (analyst, dair, reason_synthesize, report,
        …) and decides which thinking level applies. ``max_tokens`` is left
        off the request unless given: a thinking model pays its thinking out
        of that limit and every fixed cap starved one. ``compact`` is an
        optional callable ``messages -> messages`` the ladder may use as its
        last rung when the input itself makes the thinking too long.
        ``level`` forces a thinking level for this call (the capability probe
        uses it); otherwise the role's, the provider's or the learned level
        applies.

        When the model spends its whole budget thinking and answers nothing,
        the reply is retried up the starvation ladder — an explicit cap where
        the endpoint's own default cut it short, then a bounded thinking
        level, then the compacted input — and the level that answered is
        remembered for this provider, model and role, so the climb is paid
        once rather than on every call. A rung reached through a cut the
        client itself made, or one that answered only with compacted
        input, proves nothing about the level and is not remembered.
        """
        provider_name = self._provider_name_safe()
        model = self.model
        if not self.api_key and not self._base_url:
            # A registered provider without a key is a configuration error.
            # An explicit endpoint without one is a local server, which
            # takes requests with no auth header at all.
            raise LLMError(
                f"no API key for provider {provider_name or 'unconfigured'!r}; "
                f"refusing to send an unauthenticated chat request"
            )
        api = providers.CHAT_API
        try:
            api = self.provider.api or providers.CHAT_API
        except Exception:  # noqa: BLE001
            api = providers.CHAT_API
        url = (llmhub.build_responses_url(self.base_url)
               if api == providers.RESPONSES_API
               else llmhub.build_chat_url(self.base_url))

        profile = resolve_api_compat(provider_name, model)
        configured = level or self.thinking_level_for(role, profile)
        level = configured
        cap = self._cap_for(max_tokens, profile)
        self.ladder_events = []
        self._reasoning_role = role
        capped_by_ladder = False
        compacted = False
        # False once a level rung was driven by a cut the client or the
        # connection made rather than by the endpoint's own starvation.
        teaches = True
        # Cuts the client made in this call: the first is re-asked once at
        # a lower level, the second returns the reply as it is. Each rung
        # has its own time budget, so this is what bounds the call.
        client_cuts = 0
        parsed: ChatResponse | None = None
        for _ in range(2 + len(LADDER_LEVELS) + 1):
            payload = self._build_payload(
                api, model, messages, tools, cap, temperature,
                response_format, profile, level, provider_name,
                tool_choice=tool_choice)
            parsed, profile = self._send(url, payload, api, provider_name,
                                         model, profile)
            self.total_input_tokens += parsed.input_tokens
            self.total_output_tokens += parsed.output_tokens
            self.total_cached_tokens += parsed.cached_tokens or 0
            from core import usage_ledger
            usage_ledger.record(
                role=role,
                provider=(provider_name or self._usage_provider
                          or url.split("//", 1)[-1].split("/", 1)[0]),
                model=model, input_tokens=parsed.input_tokens,
                output_tokens=parsed.output_tokens,
                cached_tokens=parsed.cached_tokens or 0,
                reasoning_tokens=parsed.reasoning_tokens or 0,
                usage_reported=parsed.usage_reported,
                status=("cut" if parsed.cut_reason
                        else "starved" if parsed.starved else "ok"))
            self._record_spend(parsed.input_tokens
                               or len(json.dumps(payload)) // 4)
            if not parsed.starved:
                if not parsed.cut_reason:
                    self._note_reasoning(role, parsed)
                self._learn_from_reply(
                    provider_name, model, profile, parsed, role=role,
                    level=(level if teaches and not compacted
                           and level != configured else None))
                return parsed
            if parsed.cut_reason in CLIENT_CUTS:
                client_cuts += 1
                if client_cuts >= 2:
                    self._ladder_event("cut_returned", parsed, role, level, cap)
                    return parsed
            # ── starvation ladder ──────────────────────────────────────
            if (cap is None and parsed.finish_reason == "length"
                    and not capped_by_ladder and not parsed.cut_reason):
                # The endpoint's own default cut the reply short: give it a
                # ceiling and remember that this model needs one. A cut the
                # client or the connection made says nothing about the
                # endpoint's default.
                cap = EXPLICIT_CAP
                capped_by_ladder = True
                profile = replace(profile, needs_explicit_cap=True)
                remember_api_compat(provider_name, model, profile)
                self._ladder_event("explicit_cap", parsed, role, level, cap)
                continue
            # Only the rungs below the level this reply was asked at: a
            # climb never asks for more thinking than what just starved.
            below = (LADDER_LEVELS[LADDER_LEVELS.index(level) + 1:]
                     if level in LADDER_LEVELS else LADDER_LEVELS)
            if parsed.cut_reason:
                # From an unset level the first rung below is "high", which
                # is more thinking than most endpoints' default: a cut
                # reply is re-asked with less thinking, never more.
                below = tuple(v for v in below if v != "high")
            next_level = next(
                (v for v in below
                 if not profile.effort_values or v in profile.effort_values),
                None)
            if next_level:
                if parsed.cut_reason:
                    teaches = False
                level = next_level
                self._ladder_event("lower_level", parsed, role, level, cap)
                continue
            if compact is not None and not compacted:
                compacted = True
                messages = compact(messages)
                self._ladder_event("compact_input", parsed, role, level, cap)
                continue
            break
        assert parsed is not None
        return parsed

    def _build_payload(self, api: str, model: str, messages: list[dict],
                       tools: list[dict] | None, cap: int | None,
                       temperature: float | None, response_format: dict | None,
                       profile: ApiCompatProfile, level: str | None,
                       provider_name: str, tool_choice: str | None = None) -> dict:
        if api == providers.RESPONSES_API:
            from core.responses_api import build_responses_payload
            return build_responses_payload(
                model=model, messages=messages, max_tokens=cap,
                temperature=temperature, tools=tools,
                send_temperature=profile.send_temperature,
                reasoning_effort=level)
        payload = build_chat_payload(
            model=model, messages=messages, max_tokens=cap,
            temperature=temperature, tools=tools, provider=provider_name,
            profile=profile, thinking_level=level,
            response_format=response_format, tool_choice=tool_choice)
        if self.stream and "stream" not in profile.drop_params:
            payload["stream"] = True
            if "stream_options" not in profile.drop_params:
                payload["stream_options"] = {"include_usage": True}
        return payload

    def _note_reasoning(self, role: str, parsed: ChatResponse) -> None:
        seen = len(parsed.reasoning or "")
        if seen > self._reasoning_seen.get(role, 0):
            self._reasoning_seen[role] = seen

    def _reasoning_limit(self) -> int:
        seen = self._reasoning_seen.get(self._reasoning_role, 0)
        if seen < REASONING_RUNAWAY_FLOOR_CHARS:
            return 0
        return REASONING_RUNAWAY_FACTOR * seen

    def _request(self, url: str, payload: dict, timeout: float,
                 deadline: float | None = None):
        """One request on the wire. A streamed chat completion is folded
        back into the body a single reply carries, so everything after
        this reads one shape; a gateway that answers a stream request with
        a plain body, or with an error, is read as such."""
        headers = self._headers()
        dump = _wire_dump(payload)
        if not payload.get("stream"):
            resp = httpx.post(url, json=payload, headers=headers, timeout=timeout)
            if dump:
                dump.with_suffix(".reply.txt").write_text(
                    str(getattr(resp, "text", "")), encoding="utf-8")
            return resp
        with httpx.stream("POST", url, json=payload, headers=headers,
                          timeout=timeout) as resp:
            status = resp.status_code if isinstance(resp.status_code, int) else 200
            ctype = str((getattr(resp, "headers", None) or {}).get(
                "content-type", "")).lower()
            if status != 200 or "text/event-stream" not in ctype:
                read = getattr(resp, "read", None)
                if callable(read):
                    read()
                if dump:
                    dump.with_suffix(".reply.txt").write_text(
                        str(getattr(resp, "text", "")), encoding="utf-8")
                return resp
            lines = resp.iter_lines()
            if dump:
                lines = _tee_lines(lines, dump.with_suffix(".stream.txt"))
            return _FoldedReply(status, resp.headers,
                                assemble_stream(lines,
                                                reasoning_limit=self._reasoning_limit(),
                                                deadline=deadline))

    def _ladder_event(self, rung: str, parsed: ChatResponse, role: str,
                      level: str | None, cap: int | None) -> None:
        self.ladder_events.append({
            "rung": rung, "role": role, "level": level, "cap": cap,
            "finish_reason": parsed.finish_reason,
            "cut": parsed.cut_reason,
            "reasoning_tokens": parsed.reasoning_tokens,
            "completion_tokens": parsed.output_tokens,
        })

    @staticmethod
    def _learn_from_reply(provider_name: str, model: str,
                          profile: ApiCompatProfile, parsed: ChatResponse,
                          role: str = "", level: str | None = None) -> None:
        """Persist what a successful reply proved: that the model thinks,
        and the level the ladder had to step to for ``role`` (None when
        the call answered where it opened, or the climb proves nothing)."""
        learned = profile
        if parsed.thinking_observed and not learned.reasoning_observed:
            learned = replace(learned, reasoning_observed=True)
        if role and level and learned.level_by_role.get(role) != level:
            learned = replace(learned, level_by_role={**learned.level_by_role,
                                                     role: level})
        if learned is not profile:
            remember_api_compat(provider_name, model, learned)

    def _send(self, url: str, payload: dict, api: str, provider_name: str,
              model: str, profile: ApiCompatProfile
              ) -> tuple[ChatResponse, ApiCompatProfile]:
        """One request with retries, rate-limit waits, WAF handling and
        400-adaptation. Returns the parsed reply and the profile after any
        adaptation this request taught."""
        # ~4 chars/token is close enough to pace the request before sending.
        estimated_tokens = len(json.dumps(payload)) // 4
        # Carries a 400-round's learned drop_params to the success-path
        # remember_api_compat() below — that call rebuilds a profile from
        # `payload`'s own shape via profile_from_payload(), which can't
        # reconstruct a bare drop (see adapt_payload_for_400's docstring),
        # so it must be threaded through explicitly instead of defaulting
        # back to empty.
        current_drop_params = profile.drop_params

        # Everything below — attempts, backoff sleeps, 429 waits — must fit
        # inside one turn-time budget so a wedged hub call can never freeze
        # the run.
        deadline = (time.monotonic() + self.turn_time_budget
                    if self.turn_time_budget > 0 else None)

        def _remaining() -> float | None:
            return None if deadline is None else deadline - time.monotonic()

        def _sleep(seconds: float) -> None:
            rem = _remaining()
            time.sleep(seconds if rem is None else max(0.0, min(seconds, rem)))

        last_error: Exception | None = None
        attempt = 0
        rate_wait = 0.0
        adapt_rounds = 0
        while attempt < MAX_RETRIES:
            rem = _remaining()
            if rem is not None and rem <= 0:
                raise LLMDeadlineError(
                    f"Turn time budget of {self.turn_time_budget:.0f}s "
                    f"(ATLAS_AGENT_TURN_TIME_BUDGET) exhausted after "
                    f"{attempt} attempt(s); last error: {last_error}")
            self._pace(estimated_tokens)
            # The streamed reply's own bound: its share of the budget from
            # the moment it is sent, never past the request's deadline.
            reply_deadline = None
            if self.turn_time_budget > 0:
                reply_deadline = time.monotonic() + self.turn_time_budget * REPLY_SHARE
                if deadline is not None:
                    reply_deadline = min(reply_deadline, deadline)
            try:
                resp = self._request(url, payload,
                                     (self.timeout if rem is None
                                      else max(1.0, min(self.timeout, rem))),
                                     deadline=reply_deadline)
            except httpx.HTTPError as e:
                last_error = e
                attempt += 1
                _sleep(min(2 ** attempt * 2, 30))
                continue
            # Test doubles and thin gateways do not always carry a numeric
            # status; anything that is not one is read as success and left
            # to the parser.
            status = resp.status_code if isinstance(resp.status_code, int) else 200
            if status == 429:
                delay = rate_limit_delay(resp.text, resp.headers, attempt)
                if rate_wait + delay > RATE_LIMIT_WAIT_BUDGET:
                    raise LLMError(
                        f"Rate-limited for over {RATE_LIMIT_WAIT_BUDGET:.0f}s "
                        f"(ATLAS_AGENT_RATE_LIMIT_WAIT): {resp.text[:300]}")
                rate_wait += delay
                _sleep(delay)
                continue  # rate limits don't consume regular attempts
            if status in RETRYABLE_STATUS:
                last_error = LLMError(
                    f"HTTP {status} from {url}: {resp.text[:300]}")
                attempt += 1
                _sleep(rate_limit_delay(resp.text, resp.headers, attempt))
                continue
            if status == 418 or (status == 403
                                 and _WAF_NOTICE_RE.search(resp.text or "")):
                raise WAFBlockedError(
                    f"HTTP {status}: request blocked by the provider's "
                    f"web application firewall (likely attack-like "
                    f"strings in forensic content)")
            if status == 400 and adapt_rounds < _MAX_ADAPT_ROUNDS:
                adapted = adapt_payload_for_400(
                    payload, resp.text, prior_drop_params=profile.drop_params,
                    profile=profile)
                if adapted is not None:
                    payload, profile = adapted
                    current_drop_params = profile.drop_params
                    adapt_rounds += 1
                    remember_api_compat(provider_name, model, profile)
                    estimated_tokens = len(json.dumps(payload)) // 4
                    continue
            if status >= 400:
                raise LLMError(
                    f"HTTP {status} from {url}: {resp.text[:1000]}")
            # Success — persist learned shape after adaptation, or promote a
            # soft first-guess that actually worked (so model switches stick).
            if adapt_rounds or profile.source == "soft":
                profile = profile_from_payload(
                    payload, drop_params=current_drop_params, base=profile)
                remember_api_compat(provider_name, model, profile)
            parsed = (
                parse_responses(resp.json())
                if api == providers.RESPONSES_API
                else parse_response(resp.json())
            )
            return parsed, profile
        raise LLMTransportError(f"provider {provider_name!r} request failed after "
                                f"{MAX_RETRIES} attempts: {last_error}")

    def list_models(self) -> list[str]:
        url = llmhub.build_models_url(self.base_url)
        resp = httpx.get(url, headers=self._headers(), timeout=60.0)
        if resp.status_code >= 400:
            raise LLMError(f"HTTP {resp.status_code} from {url}: {resp.text[:500]}")
        data = resp.json().get("data") or []
        return sorted(m.get("id", "") for m in data if m.get("id"))
