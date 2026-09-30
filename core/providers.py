"""Named model providers.

the LLM hub (`llmhub`, configured via `LLMHUB_*`) is a first-class
built-in: it stays selectable in the wizard and the dashboard Config page,
and `resolve("llmhub")` still reads the hub vars. It is **not** assumed
when nothing has been chosen.

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

from core import llmhub

# Built-in the LLM hub — selectable, never an implicit fallback.
HUB_NAME = "llmhub"
# Back-compat alias: older call sites and tests import DEFAULT_NAME.
DEFAULT_NAME = HUB_NAME

# OpenAI-compatible endpoints take a bearer token. A gateway that wants a
# different header can say so per provider (ATLAS_PROVIDER_<NAME>_AUTH_HEADER /
# _AUTH_PREFIX) instead of needing a code change.
DEFAULT_AUTH_HEADER = "Authorization"
DEFAULT_AUTH_PREFIX = "Bearer "

# Transport for LLMHubClient. "chat" is Chat Completions (default, universal).
# "responses" is OpenAI's POST /v1/responses — opt-in per provider only.
CHAT_API = "chat"
RESPONSES_API = "responses"


def parse_llm_api(raw: str | None) -> str:
    """Resolve a provider API dialect. Unknown/empty → Chat Completions.

    Model names are never consulted. An OpenAI-compatible base URL is not
    evidence of Responses support.
    """
    v = (raw or "").strip().lower().replace("-", "_")
    if v in ("responses", "response"):
        return RESPONSES_API
    return CHAT_API

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


class UnknownProvider(ValueError):
    """A provider name that is neither `llmhub` nor declared in ATLAS_PROVIDERS.

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


@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str
    api_key: str
    model: str
    auth_header: str = DEFAULT_AUTH_HEADER
    auth_prefix: str = DEFAULT_AUTH_PREFIX
    api: str = CHAT_API

    def chat_url(self) -> str:
        if self.api == RESPONSES_API:
            return llmhub.build_responses_url(self.base_url)
        return llmhub.build_chat_url(self.base_url)

    def models_url(self) -> str:
        return llmhub.build_models_url(self.base_url)

    def headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers[self.auth_header] = f"{self.auth_prefix}{self.api_key}"
        return headers


def _infix(name: str) -> str:
    return name.strip().upper().replace("-", "_")


def var(name: str, suffix: str) -> str:
    """Env var carrying `suffix` for provider `name` (e.g. BASE_URL)."""
    return f"ATLAS_PROVIDER_{_infix(name)}_{suffix}"


# The thinking level a provider is pinned to. "auto" (or unset) sends nothing
# and lets the request path learn a level from a starved reply.
THINKING_VALUES = ("auto", "low", "medium", "high")


def thinking_var(name: str) -> str:
    return "LLMHUB_THINKING" if (name or "").strip() == HUB_NAME else var(name, "THINKING")


def thinking_level(name: str) -> str:
    """The level pinned for provider ``name``, "" when it is on auto."""
    value = (os.environ.get(thinking_var(name)) or "").strip().lower()
    return "" if value in ("", "auto", "default") else value


def _split(raw: str) -> list[str]:
    return [part.strip() for part in raw.replace("\n", ",").split(",")
            if part.strip()]


def declared() -> list[str]:
    """Well-formed provider names from ATLAS_PROVIDERS, order preserved.

    `llmhub` is the built-in hub name (LLMHUB_* vars), so it is dropped here
    even if listed. Malformed entries are skipped rather than raised — see
    malformed().
    """
    out: list[str] = []
    for name in _split(os.environ.get("ATLAS_PROVIDERS") or ""):
        if name == HUB_NAME or name in out:
            continue
        if _NAME_RE.match(name):
            out.append(name)
    return out


def malformed() -> list[str]:
    """Entries in ATLAS_PROVIDERS that are not usable provider names.

    Kept separate from declared() so a typo cannot crash an import-time
    backend resolution, while `atlas doctor` can still report it out loud.
    """
    return [name for name in _split(os.environ.get("ATLAS_PROVIDERS") or "")
            if name != HUB_NAME and not _NAME_RE.match(name)]


def names() -> list[str]:
    """Every selectable provider name. Hub first (available, not selected)."""
    return [HUB_NAME] + declared()


def is_declared(name: str) -> bool:
    return (name or "").strip() in names()


def resolve(name: str = "") -> Provider:
    """Resolve a provider by name.

    An empty name is "not configured" — it does not fall through to the hub.
    Pass ``llmhub`` explicitly to use the LLM hub.
    """
    name = (name or "").strip()
    if not name:
        raise ProviderNotConfigured(
            "no model provider configured. Set ATLAS_AGENT_PROVIDER (or the "
            "role's env var) to a provider name, or run `atlas provider setup` "
            "/ Settings -> Providers in the dashboard. Telekom LLM Hub is available as "
            f"{HUB_NAME!r} if you select it explicitly."
        )
    if name == HUB_NAME:
        return Provider(
            name=HUB_NAME,
            base_url=llmhub.base_url(),
            api_key=llmhub.api_key(),
            model=llmhub.model(),
            api=parse_llm_api(os.environ.get("LLMHUB_API")),
        )
    if name not in declared():
        raise UnknownProvider(
            f"unknown model provider {name!r}; known: {', '.join(names())}. "
            f"Add it to ATLAS_PROVIDERS and set {var(name, 'BASE_URL')}.")
    base_url = (os.environ.get(var(name, "BASE_URL")) or "").strip()
    if not base_url:
        raise UnknownProvider(
            f"provider {name!r} is listed in ATLAS_PROVIDERS but "
            f"{var(name, 'BASE_URL')} is not set.")
    header = ((os.environ.get(var(name, "AUTH_HEADER")) or "").strip()
              or DEFAULT_AUTH_HEADER)
    prefix = os.environ.get(var(name, "AUTH_PREFIX"))
    return Provider(
        name=name,
        base_url=base_url.rstrip("/"),
        api_key=(os.environ.get(var(name, "API_KEY")) or "").strip(),
        model=(os.environ.get(var(name, "MODEL")) or "").strip(),
        auth_header=header,
        auth_prefix=resolve_auth_prefix(header, prefix),
        api=parse_llm_api(os.environ.get(var(name, "API"))),
    )


def default() -> Provider:
    """The built-in hub provider. Callers must have chosen `llmhub` already."""
    return resolve(HUB_NAME)


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
        if name == "llmhub":
            try:
                from core import llmhub
                return llmhub.model() or ""
            except Exception:  # noqa: BLE001
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
    return {"analyst": analyst, "reason": reason, "dair": dair,
            "report": report, "review": review}


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
