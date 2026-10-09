"""LLM provider setup — the logic behind `atlas provider setup`.

Deliberately free of any interactive I/O (no input()/print()) so the same
functions can drive both the terminal wizard (agent/cli.py's
cmd_provider_setup) and, later, a browser dashboard's HTTP handlers without
duplicating the registration/probe/role-assignment logic — that's the seam
mentioned in the project's standalone-installer plan. A dashboard route
would: render PRESETS as choices, collect the same fields a form would need,
call register_provider_updates()/probe()/role_updates(), then write with
core.envfile exactly as the CLI wizard does below.

Secrets are handled the same way `atlas provider use` already does: this
module computes what needs writing but never decides *where* a key goes
(keyring vs .env) — that choice, and the actual key material, stays with the
caller. See cmd_provider_setup for how the CLI wizard makes that choice.
"""
from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from core import providers

# Which env var carries the provider choice for each model surface. Single
# source of truth — agent/cli.py's `provider list`/`provider use` import this
# rather than keeping a second copy.
PROVIDER_ROLE_VARS = {
    "analyst": "ATLAS_AGENT_PROVIDER",
    "reviewer": "ATLAS_REVIEW_PROVIDER",
    "report": "ATLAS_REPORT_PROVIDER",
    "reason": "REASON_BACKEND",
    "dair": "DAIR_BACKEND",
}

# The explicit model override each role reads BEFORE its provider's own model
# (`os.environ.get(VAR) or provider.model` in agent/llm.py, tools/reasoning.py,
# tools/dair.py and agent/review.py). Nothing in Atlas writes these — an
# operator sets them by hand, or a harness passes them in a child env — so a
# stale one silently outranks every model chosen here. The report role has no
# override: it always takes its provider's model.
ROLE_MODEL_VARS = {
    "analyst": "ATLAS_AGENT_MODEL",
    "reviewer": "ATLAS_REVIEW_MODEL",
    "reason": "REASON_MODEL",
    "dair": "DAIR_MODEL",
}


def shadowing_model_vars(env: Mapping[str, str],
                         roles: Iterable[str] | None = None) -> dict[str, str]:
    """`{role: var}` for every role whose model override is set in `env`.

    A set override means the role runs that model whatever provider it is
    assigned to, so the assignment alone does not describe the run. Pass
    `roles` to ask about specific ones; omit it to scan all four.
    """
    wanted = None if roles is None else set(roles)
    return {role: var for role, var in ROLE_MODEL_VARS.items()
            if (wanted is None or role in wanted)
            and (env.get(var) or "").strip()}


@dataclass(frozen=True)
class ProviderPreset:
    """One entry in the wizard's "what are you connecting to?" menu."""
    id: str
    label: str
    description: str
    base_url: str = ""       # "" = user must supply one (local/custom)
    default_model: str = ""  # "" = user must pick/type one
    needs_api_key: bool = True
    # No preset is pre-selected. The operator must pick one explicitly —
    # the LLM hub is available, not assumed.
    default_choice: bool = False
    notes: str = ""
    # The request shape the client starts from for this vendor (see
    # agent.llm.ApiCompatProfile): how a thinking level is spelled, which
    # values the vendor documents, and which reply fields it wants back in
    # the history. Learned refinements override these.
    thinking_control: str = "reasoning_effort"
    effort_values: tuple[str, ...] = ()
    echo_fields: tuple[str, ...] = ()
    # False where the vendor documents a sampling temperature as refused by
    # its current models, so the first request does not pay the 400.
    send_temperature: bool = True
    # How the shape was verified: "live" (checked against a running
    # endpoint), "docs" (the vendor's documentation only) or "" (no fixed
    # endpoint to check: the shape is learned from the server in use).
    evidence: str = "live"


# Dashboard / wizard identity fields that must never be stored as a model id
# (browser autofill of the Config "Users" role into the LLM model box).
IDENTITY_MODEL_IDS = frozenset({"admin", "analyst", "viewer"})


def is_identity_model_id(model: str) -> bool:
    """True when `model` is a dashboard role/username, not a catalogue id."""
    return (model or "").strip().casefold() in IDENTITY_MODEL_IDS


# Order is menu order. Every backend here is a first-class, equally-supported
# choice. None is pre-selected.
PRESETS: tuple[ProviderPreset, ...] = (
    ProviderPreset(
        id="llmhub",
        label="Telekom LLM Hub",
        description="T-Systems LLM Hub — api key from the Hub portal.",
        base_url="https://llm-server.llmhub.t-systems.net/v2",
        default_model="GLM-5.2",
        needs_api_key=True,
        notes="Atlas was developed and is most tested against z.ai GLM-5.2 "
              "served through this hub; every other backend here is fully "
              "supported and equally maintained.",
    ),
    ProviderPreset(
        id="openai",
        label="OpenAI (hosted)",
        description="api.openai.com — any current chat-completions model.",
        base_url="https://api.openai.com/v1",
        default_model="",
        needs_api_key=True,
        notes="Talks to OpenAI's Chat Completions API by default. To use "
              "the Responses API on this provider only, set "
              "ATLAS_PROVIDER_<NAME>_API=responses after setup. Atlas never "
              "guesses Responses from a model id; other backends stay on "
              "Chat Completions.",
    ),
    ProviderPreset(
        id="openrouter",
        label="OpenRouter",
        description="openrouter.ai — OpenAI-compatible catalogue of hosted models.",
        base_url="https://openrouter.ai/api/v1",
        default_model="",
        needs_api_key=True,
        notes="Model ids look like openai/gpt-4o-mini or anthropic/claude-sonnet-4, "
              "not a username or dashboard role. Use Test connection to list live ids.",
        thinking_control="reasoning_object",
    ),
    ProviderPreset(
        id="anthropic",
        label="Anthropic (OpenAI-compatible layer)",
        description="api.anthropic.com — Claude through Anthropic's OpenAI SDK layer.",
        base_url="https://api.anthropic.com/v1",
        default_model="",
        needs_api_key=True,
        notes="Anthropic calls this layer test-grade; for production, reach Claude "
              "through OpenRouter or the LLM Hub. reasoning_effort is ignored here, "
              "so a thinking level is sent as a thinking budget, which only Haiku 4.5 "
              "takes: the newer models refuse a budget and any temperature, Atlas "
              "stops sending one after their first refusal, and they think at their "
              "own default.",
        thinking_control="thinking_budget",
        send_temperature=False,
        evidence="docs",
    ),
    ProviderPreset(
        id="zai",
        label="Z.ai (GLM)",
        description="api.z.ai — GLM models from Z.ai directly.",
        base_url="https://api.z.ai/api/paas/v4",
        default_model="",
        needs_api_key=True,
        notes="GLM-5.3 cannot switch thinking off; levels are low, high and max.",
        thinking_control="thinking_type",
        effort_values=("low", "high", "max"),
        evidence="docs",
    ),
    ProviderPreset(
        id="deepseek",
        label="DeepSeek",
        description="api.deepseek.com — DeepSeek models directly.",
        base_url="https://api.deepseek.com",
        default_model="",
        needs_api_key=True,
        notes="Thinking is on by default. With tools the model's reasoning_content "
              "is sent back on later turns, as DeepSeek requires.",
        thinking_control="thinking_type",
        echo_fields=("reasoning_content",),
        evidence="docs",
    ),
    ProviderPreset(
        id="gemini",
        label="Google Gemini (OpenAI-compatible endpoint)",
        description="generativelanguage.googleapis.com — Gemini through its OpenAI endpoint.",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        default_model="",
        needs_api_key=True,
        notes="Levels are minimal, low, medium and high. Unsupported options are "
              "ignored silently rather than refused.",
        effort_values=("minimal", "low", "medium", "high"),
        evidence="docs",
    ),
    ProviderPreset(
        id="qwen",
        label="Alibaba Model Studio (Qwen)",
        description="DashScope compatible mode — Qwen models directly.",
        base_url="https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        default_model="",
        needs_api_key=True,
        notes="The base URL is region-specific; take it from your Model Studio "
              "workspace. Thinking is switched with enable_thinking.",
        thinking_control="enable_thinking",
        evidence="docs",
    ),
    ProviderPreset(
        id="xai",
        label="xAI (Grok)",
        description="api.x.ai — Grok models directly.",
        base_url="https://api.x.ai/v1",
        default_model="",
        needs_api_key=True,
        notes="Levels are low, medium, high and xhigh; thinking cannot be switched off.",
        effort_values=("low", "medium", "high", "xhigh"),
        evidence="docs",
    ),
    ProviderPreset(
        id="meta",
        label="Meta Llama API",
        description="api.llama.com — Llama models through Meta's OpenAI-compatible path.",
        base_url="https://api.llama.com/compat/v1",
        default_model="",
        needs_api_key=True,
        notes="No thinking control; the level setting is ignored.",
        thinking_control="none",
        evidence="docs",
    ),
    ProviderPreset(
        id="mistral",
        label="Mistral",
        description="api.mistral.ai — Mistral models directly.",
        base_url="https://api.mistral.ai/v1",
        default_model="",
        needs_api_key=True,
        notes="Mistral takes only none and high as levels; anything else is stepped to high.",
        effort_values=("none", "high"),
    ),
    ProviderPreset(
        id="ollama",
        label="Ollama",
        description="A local Ollama server through its OpenAI-compatible endpoint.",
        base_url="http://localhost:11434/v1",
        default_model="",
        needs_api_key=False,
        notes="tool_choice is not supported; Atlas drops it after the first refusal.",
        effort_values=("none", "low", "medium", "high", "max"),
        evidence="docs",
    ),
    ProviderPreset(
        id="local",
        label="Local / self-hosted (vLLM, Ollama, LM Studio, text-gen-webui, ...)",
        description="Any OpenAI-compatible server on your own network.",
        base_url="http://localhost:8000/v1",
        default_model="",
        needs_api_key=False,
        notes="API key is usually blank for a local server (leave empty).",
        evidence="",
    ),
    ProviderPreset(
        id="custom",
        label="Other (any OpenAI-compatible gateway)",
        description="Full manual control — base URL, key, model, auth style.",
        base_url="",
        default_model="",
        needs_api_key=True,
        notes="For a non-Bearer auth header or prefix, set auth_header/"
              "auth_prefix on the SetupChoice — see core/providers.py.",
        evidence="",
    ),
)

_BY_ID = {p.id: p for p in PRESETS}


def preset_profile(preset_id: str) -> dict:
    """The request-shape fields a preset declares, as ApiCompatProfile
    keyword arguments; {} for an unknown preset or one with nothing to say."""
    p = _BY_ID.get((preset_id or "").strip())
    if p is None:
        return {}
    fields = {}
    if p.thinking_control != "reasoning_effort":
        fields["thinking_control"] = p.thinking_control
    if p.effort_values:
        fields["effort_values"] = tuple(p.effort_values)
    if p.echo_fields:
        fields["echo_fields"] = tuple(p.echo_fields)
    if not p.send_temperature:
        fields["send_temperature"] = False
    return fields


def preset(preset_id: str) -> ProviderPreset:
    try:
        return _BY_ID[preset_id]
    except KeyError:
        raise KeyError(
            f"unknown preset {preset_id!r}; known: {', '.join(_BY_ID)}"
        ) from None


_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


def validate_name(name: str) -> str | None:
    """Error string, or None if `name` is a usable provider name.

    Registering "llmhub" itself is always fine (it just (re)writes the
    LLMHUB_* vars) — every other name has to pass the same pattern
    core/providers.py's declared() enforces, so a wizard-created provider
    can never end up silently invisible to it.
    """
    name = (name or "").strip()
    if not name:
        return "A name is required."
    if name == providers.DEFAULT_NAME:
        return None
    if not _NAME_RE.match(name):
        return ("Use letters, digits, '-', '_' only, starting with a "
                "letter or digit.")
    return None


@dataclass
class SetupChoice:
    """One wizard screen's worth of input — whether typed at a terminal or
    submitted from a future dashboard form."""
    preset_id: str
    name: str = ""                 # ignored when preset_id == "llmhub"
    base_url: str = ""
    model: str = ""
    auth_header: str = ""          # "" = provider default
    auth_prefix: str | None = None  # None or "" = provider default (Bearer)
    roles: tuple[str, ...] = tuple(PROVIDER_ROLE_VARS)
    # How hard this provider's models are asked to think: one of
    # providers.THINKING_VALUES. "auto" sends nothing and lets the request
    # path learn a level from a starved reply.
    thinking: str = "auto"


def key_env_var(name: str) -> str:
    """The env var an API key for provider `name` would be stored under."""
    if name == providers.DEFAULT_NAME:
        return "LLMHUB_API_KEY"
    return providers.var(name, "API_KEY")


def register_provider_updates(choice: SetupChoice) -> dict[str, str]:
    """Compute the (non-secret) .env updates for `choice`.

    Never includes the API key — the caller decides where that goes
    (keyring vs .env; see cmd_provider_setup). Caller writes the result with
    core.envfile.set_values().
    """
    # No explicit name: fall back to the preset id (e.g. "openai"), not the
    # global default provider name — only the "llmhub" preset's id coincides
    # with providers.DEFAULT_NAME, so this keeps that case unchanged.
    name = (choice.name or "").strip() or choice.preset_id
    err = validate_name(name)
    if err:
        raise ValueError(err)
    base_url = (choice.base_url or "").strip()
    if not base_url:
        raise ValueError("A base URL is required.")
    model = (choice.model or "").strip()
    thinking = (choice.thinking or "auto").strip().lower()
    if thinking not in providers.THINKING_VALUES:
        raise ValueError(
            f"{choice.thinking!r} is not a thinking level. Use one of: "
            + ", ".join(providers.THINKING_VALUES))

    if name == providers.DEFAULT_NAME:
        updates = {"LLMHUB_BASE_URL": base_url}
        if model:
            updates["LLMHUB_MODEL"] = model
        if thinking != "auto":
            updates["LLMHUB_THINKING"] = thinking
        return updates

    updates = {
        providers.var(name, "BASE_URL"): base_url,
    }
    if model:
        updates[providers.var(name, "MODEL")] = model
    if thinking != "auto":
        updates[providers.var(name, "THINKING")] = thinking
    # A vendor preset with a request shape of its own is remembered by id, so
    # the client starts from that shape before it has learned anything.
    if preset_profile(choice.preset_id) and choice.preset_id != name:
        updates[providers.var(name, "PRESET")] = choice.preset_id
    if choice.auth_header.strip():
        updates[providers.var(name, "AUTH_HEADER")] = choice.auth_header.strip()
    # Blank prefix is "not configured" — do not write AUTH_PREFIX= or
    # OpenAI-compatible gateways receive a bare token. A non-empty prefix
    # (including a trailing space, e.g. "Token ") is written as given.
    if choice.auth_prefix is not None and choice.auth_prefix != "":
        updates[providers.var(name, "AUTH_PREFIX")] = choice.auth_prefix
    return updates


def declared_providers_update(existing: list[str], add_name: str) -> dict[str, str]:
    """The ATLAS_PROVIDERS update to add `add_name`, or {} if already listed.

    `existing` is providers.declared() from the .env *before* this write —
    call it before register_provider_updates() touches anything else.
    """
    if add_name == providers.DEFAULT_NAME or add_name in existing:
        return {}
    return {"ATLAS_PROVIDERS": ",".join(existing + [add_name])}


def undeclare_provider_update(existing: list[str], name: str) -> dict[str, str]:
    """The ATLAS_PROVIDERS update to remove `name`, or {} if it wasn't
    declared (mirrors declared_providers_update, in reverse)."""
    if name not in existing:
        return {}
    return {"ATLAS_PROVIDERS": ",".join(n for n in existing if n != name)}


def role_updates(name: str, roles: tuple[str, ...],
                 env: Mapping[str, str] | None = None) -> dict[str, str]:
    """.env updates so the given roles point at provider `name`.

    Also clears (sets to "") any role currently assigned to `name` but not
    in `roles` — a role only ever has one provider at a time, so unchecking
    it in the dashboard must actually unassign it, not leave the old value
    in place. Roles assigned to a DIFFERENT provider are left untouched;
    this only ever writes what `name`'s own checkboxes control.

    Assigning a role also clears that role's model override (see
    ROLE_MODEL_VARS), because the override outranks the provider's model:
    without this the assignment is written and displayed but never followed,
    and the run silently uses the old model. `env` is where the current
    overrides are read from — pass the .env file's own values when they may
    differ from this process's environment.
    """
    wanted = set(roles)
    env = os.environ if env is None else env
    updates: dict[str, str] = {}
    for role, var in PROVIDER_ROLE_VARS.items():
        if role in wanted:
            updates[var] = name
        elif providers.role_name(var) == name:
            updates[var] = ""
    for var in shadowing_model_vars(env, wanted).values():
        updates[var] = ""
    return updates


def roles_losing_coverage(name: str, new_roles: tuple[str, ...]) -> list[str]:
    """Roles currently assigned to `name` that `new_roles` would leave with
    no provider at all (used both for a role-checkbox change and for
    deleting `name` outright, where `new_roles` is simply `()`)."""
    wanted = set(new_roles)
    return [role for role, var in PROVIDER_ROLE_VARS.items()
            if role not in wanted and providers.role_name(var) == name]


@dataclass
class ProbeResult:
    ok: bool
    status: int | None
    url: str
    models: list[str] = field(default_factory=list)
    error: str = ""


def probe(base_url: str, api_key: str, *, auth_header: str = "",
         auth_prefix: str | None = None, timeout: float = 20.0) -> ProbeResult:
    """Live GET /models check — the same call `atlas doctor --probe` and
    `atlas provider use` already make, factored out so the wizard can offer
    "test before you save" instead of only "fail after you save"."""
    import httpx
    from core import llmhub

    url = llmhub.build_models_url(base_url)
    header = auth_header.strip() or providers.DEFAULT_AUTH_HEADER
    prefix = providers.resolve_auth_prefix(header, auth_prefix)
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers[header] = f"{prefix}{api_key}"
    try:
        resp = httpx.get(url, headers=headers, timeout=timeout)
    except Exception as e:  # noqa: BLE001 — surfaced to the caller, not raised
        return ProbeResult(ok=False, status=None, url=url,
                           error=f"{type(e).__name__}: {e}")
    if resp.status_code >= 400:
        return ProbeResult(ok=False, status=resp.status_code, url=url,
                           error=resp.text[:300])
    models: list[str] = []
    try:
        body = resp.json()
        entries = body.get("data") if isinstance(body, dict) else body
        if isinstance(entries, list):
            models = [str(m.get("id")) for m in entries
                      if isinstance(m, dict) and m.get("id")]
    except ValueError:
        pass
    return ProbeResult(ok=True, status=resp.status_code, url=url, models=models)


# One function tool, enough to prove an endpoint returns a structured call.
_PROBE_TOOL = {
    "type": "function",
    "function": {
        "name": "list_processes",
        "description": "List the processes recorded in a memory image.",
        "parameters": {"type": "object",
                       "properties": {"image": {"type": "string"}},
                       "required": ["image"]},
    },
}
_THINKING_FIELDS = ("reasoning_content", "reasoning", "reasoning_details",
                    "thinking_blocks", "thinking")
# Roles that need a structured tool call from the model.
_ROLES_NEEDING_TOOLS = ("analyst",)

# What is not probed here, and why: the size of tool list a model answers
# with a function call. A model can fail its first turn inside a run at a
# list size it answers without trouble in a probe with a minimal prompt: the
# behaviour depends on the whole request, so a probe would learn the wrong
# size or unlearn a right one. Only the run itself can measure it, and it
# does: agent.loop cuts the list when a call fails to arrive and remembers
# the size once a call arrives at it.


@dataclass
class CapabilityProbe:
    """What three short calls say about a model: whether it answers, calls
    tools, thinks, and takes a thinking level. Each call is under 300 tokens,
    so a paid model costs a fraction of a cent."""
    ok: bool                         # the plain question was answered
    reachable: bool = False          # GET /models answered
    status: int | None = None
    models: list[str] = field(default_factory=list)
    answered: bool = False
    tool_calling: bool | None = None
    thinking_observed: bool = False
    thinking_field: str = ""
    reasoning_tokens: int = 0
    control_accepted: bool | None = None
    accepted_values: list[str] | None = None
    limit_param: str = "max_tokens"
    cap_needed: bool = False
    error: str = ""

    def roles_allowed(self) -> list[str]:
        """The provider roles this model can serve, from what it showed."""
        if not self.answered:
            return []
        return [r for r in PROVIDER_ROLE_VARS
                if r not in _ROLES_NEEDING_TOOLS or self.tool_calling]

    def to_dict(self) -> dict:
        out = {k: getattr(self, k) for k in (
            "ok", "reachable", "status", "models", "answered", "tool_calling",
            "thinking_observed", "thinking_field", "reasoning_tokens",
            "control_accepted", "accepted_values", "limit_param", "cap_needed",
            "error")}
        out["roles_allowed"] = self.roles_allowed()
        return out


def probe_capabilities(base_url: str, api_key: str, model: str, *,
                       auth_header: str = "", auth_prefix: str | None = None,
                       provider_name: str = "",
                       timeout: float = 60.0) -> CapabilityProbe:
    """Three short calls over the same client a run uses.

    1. ``GET /models`` — informational; a 401 or 404 here is not a failure
       when the chat call works.
    2. "Reply with the single word: ok" with no cap — proves the dialect,
       learns the limit parameter from a 400, shows whether the model thinks
       and in which field.
    3. The same question with one function tool — proves tool calling, which
       the analyst role needs.
    4. Only when thinking was seen: the question at the lowest bounded level,
       to learn whether the endpoint takes a level and which values it lists.

    What the calls teach (limit parameter, accepted values, a needed cap) is
    remembered for ``provider_name`` like any run's lessons.
    """
    from agent.llm import LLMHubClient

    model = (model or "").strip()
    listing = probe(base_url, api_key, auth_header=auth_header,
                    auth_prefix=auth_prefix, timeout=min(timeout, 20.0))
    out = CapabilityProbe(ok=False, reachable=listing.ok, status=listing.status,
                          models=listing.models)
    if not model:
        out.ok = listing.ok
        out.error = listing.error
        return out
    client = LLMHubClient(base_url=base_url, api_key=api_key, model=model,
                          timeout=timeout, provider=provider_name,
                          auth_header=(auth_header or "").strip(),
                          auth_prefix=auth_prefix)
    question = [{"role": "user", "content": "Reply with the single word: ok"}]
    try:
        reply = client.chat(question, role="", temperature=None)
    except Exception as e:  # noqa: BLE001 — surfaced to the caller, not raised
        out.error = f"{type(e).__name__}: {e}"
        return out
    out.answered = bool(reply.content)
    out.ok = out.answered
    out.thinking_observed = reply.thinking_observed or bool(client.ladder_events)
    out.reasoning_tokens = reply.reasoning_tokens
    out.thinking_field = next(
        (k for k in _THINKING_FIELDS if reply.raw_message.get(k)), "")
    try:
        tool_reply = client.chat(
            [{"role": "user", "content": "List the processes in m.img. Call the tool."}],
            tools=[_PROBE_TOOL], role="", temperature=None)
        out.tool_calling = bool(tool_reply.tool_calls)
    except Exception as e:  # noqa: BLE001
        out.tool_calling = False
        out.error = f"tool call: {type(e).__name__}: {e}"
    if out.thinking_observed:
        try:
            client.chat(question, role="", temperature=None, level="low")
            out.control_accepted = "reasoning_effort" not in client.profile.drop_params
        except Exception as e:  # noqa: BLE001
            out.control_accepted = False
            out.error = out.error or f"thinking level: {type(e).__name__}: {e}"
        out.accepted_values = list(client.profile.effort_values) or None
    profile = client.profile
    out.limit_param = profile.completion_limit
    out.cap_needed = profile.needs_explicit_cap
    return out
