"""
Shared request helpers: URLs a base URL serves, and the reasoning effort
each role asks for.

The Telekom LLM Hub itself is a provider profile (provider_profiles/
llmhub.toml): its default base URL and model, and the variables it is
configured through (LLMHUB_BASE_URL, LLMHUB_API_KEY with TSYSTEMS_API_KEY
as an alias, LLMHUB_MODEL), are data there. Role-specific vars
(REASON_URL/REASON_MODEL, DAIR_URL/DAIR_MODEL, ATLAS_AGENT_MODEL) always
override a provider's own, so different roles can still point at different
models on the same endpoint.
"""
from __future__ import annotations

import re


# ── per-role reasoning effort ─────────────────────────────────────────────
# Allocation, not a cap. A reasoning model returns its thinking in a field
# of its own (reasoning_content) that is paid for out of the completion
# budget and never read as the answer, so a role that thinks at length
# under a fixed budget can exhaust it before any content arrives. The
# roles whose answer is a decision over text they were given (does this
# value appear in that evidence, which tier does it support, which phase
# and work order follow from this summary) get the endpoint's low effort;
# the roles whose answer changes with thought (synthesis, hypotheses,
# planning) keep the endpoint default. ATLAS_EFFORT_<ROLE> overrides any
# role — the role name without its "reason_" prefix, e.g. ATLAS_EFFORT_DAIR,
# ATLAS_EFFORT_CITE_CHECK; "default" (or empty) sends nothing.
_DEFAULT_EFFORT: dict[str, str] = {
    "reason_cite_check": "low",
    "reason_confidence_score": "low",
    "reason_evaluate_finding": "low",
}
# The director is deliberately absent. Its answer is a ruling on where the
# investigation stands, and replaying recorded prompts against a live
# endpoint showed low effort changing that ruling on every prompt whose
# full-effort answer was stable across samples: a phase read one way at
# length and another way quickly. The roles above answer a question of
# containment against text they were handed, where thinking longer does not
# change what the text says. ATLAS_EFFORT_DAIR=low opts the director in.


def default_effort_for(role: str) -> str:
    """The level ``role`` runs at with nothing configured, "" for the
    endpoint's own. The map above is the single source; core.effort reads it
    through here rather than reaching into a private."""
    return _DEFAULT_EFFORT.get(role, "")


def reasoning_effort_for(role: str) -> str | None:
    """The reasoning_effort value to send for ``role``, or None for the
    endpoint default."""
    if not role:
        return None
    from core.envfile import env_str
    name = role.upper()
    if name.startswith("REASON_"):
        name = name[len("REASON_"):]
    value = env_str(f"ATLAS_EFFORT_{name}", _DEFAULT_EFFORT.get(role, ""))
    if value.lower() in ("", "default"):
        return None
    return value


def _strip_generation_suffix(base: str) -> str:
    b = base.rstrip("/")
    for suffix in ("/chat/completions", "/responses", "/messages"):
        if b.endswith(suffix):
            return b[: -len(suffix)]
    return b


def _versioned_base(base: str) -> str:
    """The base a generation path is appended to.

    A bare host gets ``/v1`` (the OpenAI convention). Any base that already
    carries a path is used as it is: ``/v2`` (the hub), ``/api/paas/v4``
    (Z.ai), ``/v1beta/openai`` (Gemini), ``/compat/v1`` (Meta),
    ``/compatible-mode/v1`` (DashScope). Guessing ``/v1`` under a path that
    has none produced URLs no vendor serves.
    """
    b = _strip_generation_suffix(base.rstrip("/"))
    m = re.match(r"^(https?://[^/]+)(/.*)?$", b)
    if m and not (m.group(2) or "").strip("/"):
        return m.group(1) + "/v1"
    return b


def build_chat_url(base: str) -> str:
    """Resolve a chat-completions URL from a base URL: a full endpoint is
    kept, a bare host gets ``/v1``, any other path is appended to."""
    b = base.rstrip("/")
    if b.endswith("/chat/completions"):
        return b
    return _versioned_base(b) + "/chat/completions"


def build_responses_url(base: str) -> str:
    """Resolve a Responses API URL from the same base used for Completions."""
    b = base.rstrip("/")
    if b.endswith("/responses"):
        return b
    return _versioned_base(b) + "/responses"


def build_messages_url(base: str) -> str:
    """Resolve an Anthropic Messages URL from the same base."""
    b = base.rstrip("/")
    if b.endswith("/messages"):
        return b
    return _versioned_base(b) + "/messages"


def build_models_url(base: str) -> str:
    return _versioned_base(base) + "/models"


def get_models(base: str, headers: dict, *, paging: str = "none", timeout: float = 20.0):
    """GET the model list with every page it has: (the last response, the
    entries of the pages read; None when the first body holds no list).

    paging "after_id" is the cursor style Anthropic's list uses: up to 1000
    a page, the next one after the last id while has_more. An error status
    ends the reading; the caller reads it off the response. A cursor seen
    before ends it too, so a server that repeats one cannot loop."""
    import httpx

    url = build_models_url(base)
    params = {"limit": 1000} if paging == "after_id" else None
    entries: list | None = None
    seen: set = set()
    while True:
        resp = httpx.get(url, headers=headers, timeout=timeout, **({"params": params} if params else {}))
        if resp.status_code >= 400:
            return resp, entries
        try:
            body = resp.json()
        except ValueError:
            return resp, entries
        page = body.get("data") if isinstance(body, dict) else body
        if not isinstance(page, list):
            return resp, entries
        entries = (entries or []) + [e for e in page if isinstance(e, dict)]
        cursor = body.get("last_id") if isinstance(body, dict) else None
        if paging != "after_id" or not body.get("has_more") or not cursor or cursor in seen:
            return resp, entries
        seen.add(cursor)
        params = {"limit": 1000, "after_id": cursor}
