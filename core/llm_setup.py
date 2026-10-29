"""LLM provider setup — the logic behind `atlas provider setup`.

Deliberately free of any interactive I/O (no input()/print()) so the same
functions can drive both the terminal wizard (agent/cli.py's
cmd_provider_setup) and, later, a browser dashboard's HTTP handlers without
duplicating the registration/probe/role-assignment logic — that's the seam
mentioned in the project's standalone-installer plan. A dashboard route
would: render presets() as choices, collect the same fields a form would need,
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

from core import envfile, provider_profiles, providers

# Which env var carries the provider choice for each model surface. Single
# source of truth — agent/cli.py's `provider list`/`provider use` import this
# rather than keeping a second copy.
PROVIDER_ROLE_VARS = {
    "analyst": "ATLAS_AGENT_PROVIDER",
    "reviewer": "ATLAS_REVIEW_PROVIDER",
    "report": "ATLAS_REPORT_PROVIDER",
    "reason": "REASON_BACKEND",
    "dair": "DAIR_BACKEND",
    "vision": "VISION_BACKEND",
}

# Roles an operator assigns on purpose, never by `provider use --role all`:
# the vision role's model must take images, which a text model does not.
ROLES_CHOSEN_ON_PURPOSE = ("vision",)

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
    "vision": "VISION_MODEL",
}


def shadowing_model_vars(env: Mapping[str, str],
                         roles: Iterable[str] | None = None) -> dict[str, str]:
    """`{role: var}` for every role whose model override is set in `env`.

    A set override means the role runs that model whatever provider it is
    assigned to, so the assignment alone does not describe the run. Pass
    `roles` to ask about specific ones; omit it to scan them all.
    """
    wanted = None if roles is None else set(roles)
    return {role: var for role, var in ROLE_MODEL_VARS.items()
            if (wanted is None or role in wanted)
            and (env.get(var) or "").strip()}


@dataclass(frozen=True)
class ProviderPreset:
    """One entry in the wizard's "what are you connecting to?" menu: a view
    of a provider profile (provider_profiles/), where the facts live."""
    id: str
    label: str
    description: str
    base_url: str = ""       # "" = user must supply one (local/custom)
    default_model: str = ""  # "" = user must pick/type one
    needs_api_key: bool = True
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
    # An instance of its own (the hub), configured through its own variables.
    implicit: bool = False
    # The thinking values a provider on this profile may be pinned to (the
    # profile's own levels; a model rule can change them per model).
    levels: tuple[str, ...] = providers.THINKING_VALUES

    @classmethod
    def of(cls, profile: provider_profiles.Profile) -> "ProviderPreset":
        return cls(id=profile.id, label=profile.label, description=profile.description,
                   base_url=profile.base_url, default_model=profile.default_model,
                   needs_api_key=profile.needs_api_key, notes=profile.notes,
                   thinking_control=profile.control, effort_values=tuple(profile.levels.values()),
                   echo_fields=profile.echo_fields, send_temperature=profile.send_temperature,
                   evidence=profile.evidence, implicit=profile.implicit,
                   levels=providers.selectable_levels(profile))


# Dashboard / wizard identity fields that must never be stored as a model id
# (browser autofill of the Config "Users" role into the LLM model box).
IDENTITY_MODEL_IDS = frozenset({"admin", "analyst", "viewer"})


def is_identity_model_id(model: str) -> bool:
    """True when `model` is a dashboard role/username, not a catalogue id."""
    return (model or "").strip().casefold() in IDENTITY_MODEL_IDS


def presets() -> list[ProviderPreset]:
    """The setup menu, in menu order: one entry per usable provider profile.
    Every backend here is a first-class, equally-supported choice; none is
    pre-selected."""
    return [ProviderPreset.of(p) for p in provider_profiles.menu()]


def bound_profile(preset_id: str, name: str = "") -> provider_profiles.Profile:
    """The profile a save binds ``name`` to: an implicit instance's own,
    else ``preset_id``, else the fallback. A preset no file defines raises
    ProfileError (a ValueError, in the words an unusable binding uses), so
    the writer refuses it before any probe or write."""
    return provider_profiles.implicit(name) or provider_profiles.get(
        (preset_id or "").strip() or provider_profiles.FALLBACK)


def levels_for(preset_id: str, model: str = "", name: str = "") -> tuple[str, ...]:
    """The thinking values a provider saved under ``preset_id`` may be pinned
    to for ``model``."""
    return providers.selectable_levels(bound_profile(preset_id, name), model)


def _levels_refusal(profile: provider_profiles.Profile, model: str, level: str,
                    allowed: tuple[str, ...]) -> str:
    pinned = [v for v in allowed if v != "auto"]
    takes = (" or ".join(pinned) if len(pinned) < 3 else ", ".join(pinned[:-1]) + " or " + pinned[-1]) \
        if pinned else "no level Atlas can pin"
    return (f"{profile.label} takes {takes}{' for ' + model if model else ''}, not {level!r}; "
            "auto lets Atlas learn one.")


def preset(preset_id: str) -> ProviderPreset:
    try:
        return ProviderPreset.of(provider_profiles.get(preset_id))
    except provider_profiles.ProfileError as exc:
        raise KeyError(str(exc)) from None


_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


def validate_name(name: str) -> str | None:
    """Error string, or None if `name` is a usable provider name.

    Registering an implicit profile's id ("llmhub") is always fine (it just
    (re)writes the variables that profile names) — every other name has to
    pass the same pattern
    core/providers.py's declared() enforces, so a wizard-created provider
    can never end up silently invisible to it.
    """
    name = (name or "").strip()
    if not name:
        return "A name is required."
    if provider_profiles.implicit(name) is not None:
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
    name: str = ""                 # ignored for an implicit profile ("llmhub")
    base_url: str = ""
    model: str = ""
    auth_header: str = ""          # "" = provider default
    auth_prefix: str | None = None  # None or "" = provider default (Bearer)
    roles: tuple[str, ...] = tuple(PROVIDER_ROLE_VARS)
    # How hard this provider's models are asked to think: one of
    # providers.THINKING_VALUES. "auto" sends nothing and lets the request
    # path learn a level from a starved reply.
    thinking: str = "auto"


# A provider profile's header-name rule (provider_profiles/schema.json, [auth] header).
_HEADER_RE = re.compile(r"^[A-Za-z0-9-]+$")


def field_error(label: str, value: str) -> str | None:
    """Why a provider field cannot be written to the env file, or None: a
    character that breaks the line (core.envfile.unsafe_value), or what the
    env loader (python-dotenv) would rewrite: a ``${`` it interpolates, a
    quote it strips at either end. No base URL, model, header or prefix
    holds one."""
    value = str(value or "")
    why = envfile.unsafe_value(value)
    if why:
        return f"The {label} cannot be saved: {why}."
    if "${" in value:
        return f"The {label} cannot hold '${{': the env loader would read it as a variable."
    stripped = value.strip()
    if stripped[:1] in ("'", '"') or stripped[-1:] in ("'", '"'):
        return f"The {label} cannot start or end with a quote."
    return None


def key_env_var(name: str) -> str:
    """The env var an API key for provider `name` would be stored under."""
    return providers.var(name, "API_KEY")


def register_provider_updates(choice: SetupChoice) -> dict[str, str]:
    """Compute the (non-secret) .env updates for `choice`.

    Never includes the API key — the caller decides where that goes
    (keyring vs .env; see cmd_provider_setup). Caller writes the result with
    core.envfile.set_values().
    """
    # No explicit name: fall back to the preset id (e.g. "openai").
    name = (choice.name or "").strip() or choice.preset_id
    err = validate_name(name)
    if err:
        raise ValueError(err)
    preset_id = (choice.preset_id or "").strip()
    if provider_profiles.implicit(name) is None and (other := providers.colliding_name(name)):
        raise ValueError(
            f"{name!r} would share its settings with the provider {other!r} (both are "
            f"ATLAS_PROVIDER_{provider_profiles.instance_stem(name)}_*): edit that provider, or choose "
            f"another name.")
    base_url = (choice.base_url or "").strip()
    if not base_url:
        raise ValueError("A base URL is required.")
    model = (choice.model or "").strip()
    for label, value in (("base URL", base_url), ("model", model), ("auth header", choice.auth_header or ""),
                         ("auth prefix", choice.auth_prefix or "")):
        if err := field_error(label, value):
            raise ValueError(err)
    if (choice.auth_header or "").strip() and not _HEADER_RE.match(choice.auth_header.strip()):
        raise ValueError(f"{choice.auth_header.strip()!r} is not a header name: use letters, digits and '-' "
                         "(as a provider profile's [auth] header).")
    thinking = (choice.thinking or "auto").strip().lower()
    if thinking not in providers.THINKING_VALUES:
        raise ValueError(
            f"{choice.thinking!r} is not a thinking level. Use one of: "
            + ", ".join(providers.THINKING_VALUES))
    # A pinned level is sent as written: only one the bound profile lists
    # (for this model) reaches the vendor as a level it documents.
    bound = bound_profile(preset_id, name)
    allowed = providers.selectable_levels(bound, model)
    if thinking not in allowed:
        raise ValueError(_levels_refusal(bound, model, thinking, allowed))

    if provider_profiles.implicit(name) is not None:
        # An implicit instance is configured through its profile's variables.
        updates = {providers.var(name, "BASE_URL"): base_url}
        if model:
            updates[providers.var(name, "MODEL")] = model
        if thinking != "auto":
            updates[providers.var(name, "THINKING")] = thinking
        return updates

    updates = {
        providers.var(name, "BASE_URL"): base_url,
    }
    if model:
        updates[providers.var(name, "MODEL")] = model
    if thinking != "auto":
        updates[providers.var(name, "THINKING")] = thinking
    # The provider profile is remembered by id (unless it is the fallback),
    # also when the name says it: a profile file that later disappears then
    # makes the provider unusable with the reason, instead of letting it
    # bind to the fallback without a word.
    if preset_id and preset_id != provider_profiles.FALLBACK:
        updates[providers.var(name, "PRESET")] = preset_id
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
    if provider_profiles.implicit(add_name) is not None or add_name in existing:
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
    timed_out: bool = False

    @property
    def reached(self) -> bool:
        """An HTTP status came back, any status. Not reached and not timed
        out: no answer at all (refused, no such host, a TLS failure)."""
        return self.status is not None


def probe(base_url: str, api_key: str, *, auth_header: str = "",
         auth_prefix: str | None = None, timeout: float = 20.0,
         profile_id: str = "") -> ProbeResult:
    """Live GET /models check — the same call `atlas doctor --probe` and
    `atlas provider use` already make, factored out so the wizard can offer
    "test before you save" instead of only "fail after you save". With a
    profile, its auth header and headers apply where the caller gives none;
    a profile that cannot be used fails the check before any request."""
    from core import llmhub

    url = llmhub.build_models_url(base_url)
    profile = None
    if profile_id:
        try:
            profile = provider_profiles.get(profile_id)
        except provider_profiles.ProfileError as exc:
            return ProbeResult(ok=False, status=None, url=url, error=str(exc))
    header, prefix = providers.auth_for(auth_header, auth_prefix, profile)
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers[header] = f"{prefix}{api_key}"
    if profile is not None:
        headers.update(profile.headers)
    try:
        resp, entries = llmhub.get_models(base_url, headers, timeout=timeout,
                                          paging=profile.models_paging if profile is not None else "none")
    except Exception as e:  # noqa: BLE001 — surfaced to the caller, not raised
        import httpx
        return ProbeResult(ok=False, status=None, url=url,
                           error=f"{type(e).__name__}: {e}",
                           timed_out=isinstance(e, httpx.TimeoutException))
    if resp.status_code >= 400:
        return ProbeResult(ok=False, status=resp.status_code, url=url,
                           error=resp.text[:300])
    models = [str(m.get("id")) for m in entries or [] if m.get("id")]
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
    reached: bool = False            # GET /models got an HTTP status back
    finished: bool = True            # every call ran inside the check's deadline

    def roles_allowed(self) -> list[str]:
        """The provider roles this model can serve, from what it showed."""
        if not self.answered:
            return []
        return [r for r in PROVIDER_ROLE_VARS
                if r not in ROLES_CHOSEN_ON_PURPOSE and (r not in _ROLES_NEEDING_TOOLS or self.tool_calling)]

    def to_dict(self) -> dict:
        out = {k: getattr(self, k) for k in (
            "ok", "reachable", "status", "models", "answered", "tool_calling",
            "thinking_observed", "thinking_field", "reasoning_tokens",
            "control_accepted", "accepted_values", "limit_param", "cap_needed", "reached", "finished",
            "error")}
        out["roles_allowed"] = self.roles_allowed()
        return out


# The whole check's bound (a check, not a run): a model that thinks answers
# well inside it, and a hung provider does not hold a worker for the full
# retry ladder of every call.
PROBE_DEADLINE = 90.0


def probe_capabilities(base_url: str, api_key: str, model: str, *,
                       auth_header: str = "", auth_prefix: str | None = None,
                       provider_name: str = "", profile_id: str = "",
                       timeout: float = 60.0, deadline: float = PROBE_DEADLINE) -> CapabilityProbe:
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
    remembered for ``provider_name`` like any run's lessons. The provider
    profile is ``profile_id`` (a provider not saved yet), else the one
    ``provider_name`` binds to.
    """
    import time
    from agent.llm import LLMHubClient

    ends = time.monotonic() + deadline
    model = (model or "").strip()
    if not profile_id and provider_name:
        try:
            profile_id = providers.resolve(provider_name).profile
        except providers.UnknownProvider:
            pass
    listing = probe(base_url, api_key, auth_header=auth_header,
                    auth_prefix=auth_prefix, timeout=min(timeout, 20.0),
                    profile_id=profile_id)
    out = CapabilityProbe(ok=False, reachable=listing.ok, status=listing.status,
                          models=listing.models, reached=listing.reached)
    if not model:
        out.ok = listing.ok
        out.error = listing.error
        return out
    if not listing.reached and not listing.timed_out:
        # No HTTP answer at all: the chat calls go to the same host and port,
        # and their retries would only repeat it. A timeout is not that.
        out.error = listing.error
        return out
    client = LLMHubClient(base_url=base_url, api_key=api_key, model=model,
                          timeout=timeout, provider=provider_name,
                          auth_header=(auth_header or "").strip(),
                          auth_prefix=auth_prefix, profile=profile_id)
    # Every request below, retries, waits and ladder re-asks included, ends
    # by the check's deadline.
    client.stop_at = ends
    unfinished = f"the check did not finish within {deadline:g} s"

    def within() -> bool:
        if ends - time.monotonic() > 1.0:
            return True
        out.finished = False
        out.error = out.error or unfinished
        return False

    def failed(e: Exception, what: str = "") -> str:
        if ends - time.monotonic() <= 1.0:
            out.finished = False
            return unfinished
        return f"{what}{type(e).__name__}: {e}"
    question = [{"role": "user", "content": "Reply with the single word: ok"}]
    if not within():
        return out
    try:
        reply = client.chat(question, role="", temperature=None)
    except Exception as e:  # noqa: BLE001 — surfaced to the caller, not raised
        out.error = failed(e)
        return out
    out.answered = bool(reply.content)
    out.ok = out.answered
    out.thinking_observed = reply.thinking_observed or bool(client.ladder_events)
    out.reasoning_tokens = reply.reasoning_tokens
    out.thinking_field = next(
        (k for k in _THINKING_FIELDS if reply.raw_message.get(k)), "")
    if not within():
        return out
    try:
        tool_reply = client.chat(
            [{"role": "user", "content": "List the processes in m.img. Call the tool."}],
            tools=[_PROBE_TOOL], role="", temperature=None)
        out.tool_calling = bool(tool_reply.tool_calls)
    except Exception as e:  # noqa: BLE001
        out.tool_calling = False
        out.error = failed(e, "tool call: ")
    if out.thinking_observed and within():
        try:
            client.chat(question, role="", temperature=None, level="low")
            out.control_accepted = "reasoning_effort" not in client.profile.drop_params
        except Exception as e:  # noqa: BLE001
            out.control_accepted = False
            out.error = out.error or failed(e, "thinking level: ")
        out.accepted_values = list(client.profile.effort_values) or None
    profile = client.profile
    out.limit_param = profile.completion_limit
    out.cap_needed = profile.needs_explicit_cap
    return out
