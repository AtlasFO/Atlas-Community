"""Named model providers.

A provider (an instance) is an endpoint, a model and a key, configured in
`.env`; what Atlas knows about the provider *type* lives in a provider
profile (core/provider_profiles.py), which the instance binds to. A profile
marked implicit (the Telekom LLM Hub, `llmhub`) is an instance of its own:
selectable without being declared, configured through the variables its
profile names (`LLMHUB_*`). It is **not** assumed when nothing has been
chosen.

A role (analyst, reviewer, report, reason, dair) uses a provider only when
its env var names one (`ATLAS_AGENT_PROVIDER`, `REASON_BACKEND`, …). An
empty role var is "not configured", never a silent fall-through to the hub.

Additional endpoints are declared in `.env`:

    ATLAS_PROVIDERS=gw-a,gw-b
    ATLAS_PROVIDER_GW_B_BASE_URL=https://…/llm/b/v1
    ATLAS_PROVIDER_GW_B_MODEL=<model id>
    # key belongs in the keyring, not in .env:
    #   bin/atlas-secret set ATLAS_PROVIDER_GW_B_API_KEY

The env-var infix is the provider name upper-cased with '-' → '_'. Listing a
name in ATLAS_PROVIDERS is what makes it selectable — `atlas doctor` and
`--provider` enumerate that list rather than guessing.

Two deliberate properties:

**Lazy.** Every lookup reads os.environ; nothing is cached and nothing runs at
import. `tools/reasoning.py` and `tools/dair.py` resolve their backend at
*import* time, and core.secrets may fill os.environ from the keyring only after
some modules are already imported.

**Named providers do not inherit the hub's model.** A missing model id raises
instead of falling back to LLMHUB_MODEL: sending `GLM-5.2` to an endpoint that
serves a different catalogue produces a confusing upstream 400, and the trace
would record a model that was never actually asked.
"""
import os
import re
from dataclasses import dataclass

from core import llmhub, provider_profiles

# OpenAI-compatible endpoints take a bearer token. A gateway that wants a
# different header can say so per provider (ATLAS_PROVIDER_<NAME>_AUTH_HEADER /
# _AUTH_PREFIX) instead of needing a code change.
DEFAULT_AUTH_HEADER = "Authorization"
DEFAULT_AUTH_PREFIX = "Bearer "

# Transport for LLMHubClient. "chat" is Chat Completions (default, universal).
# "responses" is OpenAI's POST /v1/responses — opt-in per provider only.
# "messages" is Anthropic's POST /v1/messages (core/messages_api.py).
CHAT_API = "chat"
RESPONSES_API = "responses"
MESSAGES_API = "messages"


def parse_llm_api(raw: str | None) -> str:
    """Resolve a provider API dialect. Unknown/empty → Chat Completions.

    Model names are never consulted. An OpenAI-compatible base URL is not
    evidence of Responses support.
    """
    v = (raw or "").strip().lower().replace("-", "_")
    if v in ("responses", "response"):
        return RESPONSES_API
    if v == "messages":
        return MESSAGES_API
    return CHAT_API

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


class UnknownProvider(ValueError):
    """A provider name that is neither an implicit profile nor declared in
    ATLAS_PROVIDERS, or one whose provider profile cannot be used.

    Deliberately fatal. While only one endpoint was configurable, an
    unrecognised backend name harmlessly fell through to it. With a second
    endpoint reachable, the same silence would run against the wrong model and
    still label it correctly in the trace — the one failure a forensic tool
    must not have.
    """


class ProviderNotConfigured(UnknownProvider):
    """A role env var is empty — no provider has been selected for that role."""


def resolve_auth_prefix(header: str, raw: str | None) -> str:
    """Resolve the token prefix for an Authorization-style header.

    Blank or missing AUTH_PREFIX on the default ``Authorization`` header
    means ``Bearer `` (OpenAI / OpenRouter / the hub). A custom header
    (``X-API-Key``, …) defaults to a bare token. A non-empty prefix is
    always used as written, including a trailing space.

    Public (no leading underscore): `core/llm_setup.py`'s own `probe()`
    needs the identical rule so a dashboard "Test connection" call sends
    the same header as the real `resolve()` path below would.
    """
    if raw is None or not str(raw).strip():
        if header == DEFAULT_AUTH_HEADER:
            return DEFAULT_AUTH_PREFIX
        return ""
    return raw


def auth_for(header: str = "", prefix: str | None = None,
             profile: "provider_profiles.Profile | None" = None) -> tuple[str, str]:
    """The auth header and prefix a request uses: the instance's own header
    (its prefix by resolve_auth_prefix) when it names one; else the profile's
    [auth]; else Authorization with Bearer. A non-blank prefix the instance
    gives is always used as written."""
    header = (header or "").strip()
    if header:
        return header, resolve_auth_prefix(header, prefix)
    header = (profile.auth_header if profile is not None else "") or DEFAULT_AUTH_HEADER
    if prefix is not None and str(prefix).strip():
        return header, prefix
    if profile is not None and profile.auth_prefix is not None:
        return header, profile.auth_prefix
    return header, resolve_auth_prefix(header, None)


@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str
    api_key: str
    model: str
    auth_header: str = DEFAULT_AUTH_HEADER
    auth_prefix: str = DEFAULT_AUTH_PREFIX
    api: str = CHAT_API
    # The bound profile's static [headers], sent on every request, and its id.
    headers_extra: tuple[tuple[str, str], ...] = ()
    profile: str = ""
    models_paging: str = "none"         # how the model list pages (the profile's)
    # The bound profile's word on whether this endpoint takes a key at all
    # (a local server does not). An unbound or broken provider never
    # resolves, and the fallback profile says True: fail closed.
    needs_api_key: bool = True

    @property
    def key_missing(self) -> bool:
        """No key where the provider's profile needs one: the one test every
        caller asks before it sends a request (a run start, a reviewer, the
        model list, an autofill, a report section)."""
        return self.needs_api_key and not (self.api_key or "").strip()

    def chat_url(self) -> str:
        if self.api == RESPONSES_API:
            return llmhub.build_responses_url(self.base_url)
        if self.api == MESSAGES_API:
            return llmhub.build_messages_url(self.base_url)
        return llmhub.build_chat_url(self.base_url)

    def models_url(self) -> str:
        return llmhub.build_models_url(self.base_url)

    def headers(self) -> dict:
        """Request headers: the content type, the key in the auth header, and
        the profile's static headers."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers[self.auth_header] = f"{self.auth_prefix}{self.api_key}"
        headers.update(self.headers_extra)
        return headers


# Every variable a provider instance has, by suffix: what a removal deletes
# (dashboard/config_llm.py delete_provider) and what doctor calls an orphan.
INSTANCE_SUFFIXES = ("BASE_URL", "MODEL", "THINKING", "API", "API_KEY", "PRESET", "AUTH_HEADER", "AUTH_PREFIX")


def var(name: str, suffix: str) -> str:
    """Env var carrying `suffix` for provider `name` (e.g. BASE_URL): an
    implicit profile's own variable where its [env] names one (the hub's
    LLMHUB_API_KEY), else ATLAS_PROVIDER_<NAME>_<SUFFIX>."""
    return provider_profiles.instance_var(name, suffix)


# The thinking level a provider is pinned to. "auto" (or unset) sends nothing
# and lets the request path learn a level from a starved reply.
THINKING_VALUES = ("auto", "low", "medium", "high")


def thinking_var(name: str) -> str:
    return var((name or "").strip(), "THINKING")


def selectable_levels(profile: "provider_profiles.Profile | None", model: str = "") -> tuple[str, ...]:
    """The THINKING_VALUES a provider bound to ``profile`` may be pinned to
    for ``model``: "auto" and those its [reasoning] levels list (a model
    rule's included); all of them when it lists none."""
    levels = profile.for_model(model).levels if profile is not None else {}
    if not levels:
        return THINKING_VALUES
    return tuple(v for v in THINKING_VALUES if v == "auto" or v in levels)


def thinking_level(name: str) -> str:
    """The level pinned for provider ``name``, "" when it is on auto."""
    value = (os.environ.get(thinking_var(name)) or "").strip().lower()
    return "" if value in ("", "auto", "default") else value


def _split(raw: str) -> list[str]:
    return [part.strip() for part in raw.replace("\n", ",").split(",")
            if part.strip()]


def colliding_name(name: str, names: list[str] | None = None) -> str:
    """The provider spelled otherwise whose variables ``name`` would share
    (same provider_profiles.instance_stem: "Claude-Code" and "claude_code"),
    among the declared names and the implicit profiles' ids; "" when none."""
    stem = provider_profiles.instance_stem(name)
    for other in (declared() if names is None else names) + provider_profiles.implicit_ids():
        if other != name.strip() and provider_profiles.instance_stem(other) == stem:
            return other
    return ""


def declared() -> list[str]:
    """Well-formed provider names from ATLAS_PROVIDERS, order preserved.

    An implicit profile's id (`llmhub`) is an instance of its own, configured
    through its own variables, so it is dropped here even if listed.
    Malformed entries are skipped rather than raised — see malformed().
    """
    implicit = set(provider_profiles.implicit_ids())
    out: list[str] = []
    for name in _split(os.environ.get("ATLAS_PROVIDERS") or ""):
        if name in implicit or name in out:
            continue
        if _NAME_RE.match(name):
            out.append(name)
    return out


def malformed() -> list[str]:
    """Entries in ATLAS_PROVIDERS that are not usable provider names.

    Kept separate from declared() so a typo cannot crash an import-time
    backend resolution, while `atlas doctor` can still report it out loud.
    """
    implicit = set(provider_profiles.implicit_ids())
    return [name for name in _split(os.environ.get("ATLAS_PROVIDERS") or "")
            if name not in implicit and not _NAME_RE.match(name)]


def names() -> list[str]:
    """Every selectable provider name. Implicit ones first (available, not selected)."""
    return provider_profiles.implicit_ids() + declared()


def is_declared(name: str) -> bool:
    return (name or "").strip() in names()


def resolve(name: str = "") -> Provider:
    """Resolve a provider by name.

    An empty name is "not configured" — it does not fall through to the hub.
    Pass an implicit profile's id (``llmhub``) explicitly to use it. A
    declared provider binds to its profile (provider_profiles.bind); a
    profile that cannot be used makes the provider unusable, with the reason.
    """
    name = (name or "").strip()
    if not name:
        raise ProviderNotConfigured(
            "no model provider configured. Set ATLAS_AGENT_PROVIDER (or the "
            "role's env var) to a provider name, or run `atlas provider setup` "
            "/ Settings -> Providers in the dashboard. Available without "
            f"registering, if you select one explicitly: {', '.join(provider_profiles.implicit_ids())}."
        )
    implicit = provider_profiles.implicit(name)
    if implicit is not None:
        return _implicit_provider(implicit)
    broken = provider_profiles.load().errors.get(name)
    if broken and name not in declared():
        # A profile of this name that fails its checks (a user file over the
        # hub's): say which file and why, not "unknown provider".
        raise UnknownProvider(f"provider {name!r} is unusable: {broken}")
    if name not in declared():
        raise UnknownProvider(
            f"unknown model provider {name!r}; known: {', '.join(names())}. "
            f"Add it to ATLAS_PROVIDERS and set {var(name, 'BASE_URL')}.")
    if other := colliding_name(name):
        # Neither may silently take the other's URL, model or key.
        raise UnknownProvider(
            f"provider {name!r} is unusable: it shares its variables "
            f"(ATLAS_PROVIDER_{provider_profiles.instance_stem(name)}_*) with the provider {other!r}. "
            f"Rename one of them in ATLAS_PROVIDERS, with its variables.")
    base_url = (os.environ.get(var(name, "BASE_URL")) or "").strip()
    if not base_url:
        raise UnknownProvider(
            f"provider {name!r} is listed in ATLAS_PROVIDERS but "
            f"{var(name, 'BASE_URL')} is not set.")
    try:
        profile, _rule = provider_profiles.bind(name, base_url)
    except provider_profiles.ProfileError as exc:
        raise UnknownProvider(f"provider {name!r} is unusable: {exc}") from None
    header, prefix = auth_for(os.environ.get(var(name, "AUTH_HEADER")) or "",
                              os.environ.get(var(name, "AUTH_PREFIX")), profile)
    return Provider(
        name=name,
        base_url=base_url.rstrip("/"),
        api_key=(os.environ.get(var(name, "API_KEY")) or "").strip(),
        model=(os.environ.get(var(name, "MODEL")) or "").strip(),
        auth_header=header,
        auth_prefix=prefix,
        api=parse_llm_api(os.environ.get(var(name, "API")) or profile.dialect),
        headers_extra=tuple(profile.headers.items()),
        profile=profile.id,
        models_paging=profile.models_paging,
        needs_api_key=profile.needs_api_key,
    )


def url_source(name: str) -> str:
    """Where provider ``name``'s base URL comes from: its variable, or the
    profile file whose default it is (shipped, user or merged)."""
    profile = provider_profiles.implicit(name)
    url_var = var(name, "BASE_URL")
    if profile is None or os.environ.get(url_var):
        return f"from {url_var}"
    return f"from profile {profile.id} ({profile.source}: {', '.join(profile.files)})"


def _implicit_provider(profile: provider_profiles.Profile) -> Provider:
    """An implicit profile's own instance, from the variables its [env] names
    and the defaults its [connection] states."""
    env = profile.env
    header, prefix = auth_for(profile=profile)
    return Provider(
        name=profile.id,
        base_url=(os.environ.get(env["base_url"]) or profile.base_url).rstrip("/"),
        api_key=next((os.environ[v] for v in env["api_key"] if os.environ.get(v)), ""),
        model=os.environ.get(env["model"]) or profile.default_model,
        auth_header=header,
        auth_prefix=prefix,
        api=parse_llm_api(os.environ.get(env.get("api", "")) or profile.dialect),
        headers_extra=tuple(profile.headers.items()),
        profile=profile.id,
        models_paging=profile.models_paging,
        needs_api_key=profile.needs_api_key,
    )


def role_name(*env_vars: str) -> str:
    """First non-empty provider name among `env_vars`, else "".

    An empty return means the role has not been pointed at a provider —
    callers must not treat that as `llmhub`.
    """
    for env_var in env_vars:
        value = (os.environ.get(env_var) or "").strip()
        if value:
            return value
    return ""


# Role env vars that may hold a provider name. Kept here (not imported
# from llm_setup) so this module never imports that one at call time.
_ROLE_ENV_VARS = (
    "ATLAS_AGENT_PROVIDER",
    "ATLAS_REVIEW_PROVIDER",
    "ATLAS_REPORT_PROVIDER",
    "REASON_BACKEND",
    "DAIR_BACKEND",
)


def role_models() -> dict[str, str]:
    """The model each role resolves to right now, by the precedence its
    consumer applies: an explicit ``*_MODEL`` variable outranks the
    provider's own model, and an unset provider is "not configured", never
    the hub.

    Recorded at run start, so a run can be read back with the models that
    actually served every role. An empty string means the role is not
    configured.
    """
    def _provider_model(*env_vars: str) -> str:
        name = role_name(*env_vars)
        if not name:
            return ""
        try:
            return resolve(name).model or ""
        except Exception:  # noqa: BLE001
            return ""

    def _env(name: str) -> str:
        return (os.environ.get(name) or "").strip()

    analyst = _env("ATLAS_AGENT_MODEL") or _provider_model("ATLAS_AGENT_PROVIDER")
    reason = _env("REASON_MODEL") or _provider_model("REASON_BACKEND")
    dair = _env("DAIR_MODEL") or _provider_model("DAIR_BACKEND")
    report = _provider_model("ATLAS_REPORT_PROVIDER", "ATLAS_AGENT_PROVIDER") or analyst
    # REASON_MODEL belongs to the reason role; the reviewer borrows it only
    # while it has no provider of its own. Same order as
    # agent/review.reviewer_model(), so the record matches the run.
    review = (_env("ATLAS_REVIEW_MODEL")
              or _provider_model("ATLAS_REVIEW_PROVIDER")
              or _env("REASON_MODEL") or analyst)
    # The vision role exists only with its provider (tools.images._configured):
    # VISION_MODEL overrides the id of VISION_BACKEND's provider, never alone.
    vision = (_env("VISION_MODEL") or _provider_model("VISION_BACKEND")) if role_name("VISION_BACKEND") else ""
    return {"analyst": analyst, "reason": reason, "dair": dair,
            "report": report, "review": review, "vision": vision}


def assigned() -> list[str]:
    """Provider names actually selected for a role, plus declared extras.

    `openai-compat` / `claude` are backend kinds, not provider names.
    Used by `atlas doctor --probe` so an unused hub is not contacted.
    """
    out: list[str] = []
    skip = {"openai-compat", "claude"}
    for env_var in _ROLE_ENV_VARS:
        name = role_name(env_var)
        if not name or name in skip or name in out:
            continue
        out.append(name)
    for name in declared():
        if name not in out:
            out.append(name)
    return out


def api_key_env_names() -> list[str]:
    """API-key env vars of every declared provider.

    core.secrets feeds this to the keyring loader so a gateway token can live
    in the keyring like every other Atlas credential instead of in `.env`.
    """
    return [var(name, "API_KEY") for name in declared()]
