"""LLM provider config for the dashboard Config Page — a thin wrapper over
core/llm_setup.py, core/providers.py, and core/envfile.py.

core/llm_setup.py was deliberately built with no interactive I/O "so a
future browser dashboard can drive the same calls from HTTP handlers
instead of terminal prompts" (its own docstring) — this module is that
dashboard. Every write follows agent/cli.py's cmd_provider_use /
cmd_provider_setup ordering exactly: validate -> probe -> only then write,
so the config page can never save a provider config that's already known
not to work.

core/envfile.py owns the write lock for .env (see its lock() docstring) so
that concurrent admin requests — including ones landing on a different
config page, like OSINT or mail — can't race and drop one of the changes.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

from core import envfile, providers
from core import llm_setup as ls

_REPO_ROOT = Path(__file__).resolve().parents[1]


class ConfigError(Exception):
    """Raised for validation/precondition failures — safe to show the admin."""


def _env_path() -> Path:
    path = envfile.resolve(_REPO_ROOT)
    if not path.is_file():
        raise ConfigError(
            f"no .env at {path} — create it first (cp .env.example .env)")
    return path


def presets() -> list[dict]:
    return [
        {"id": p.id, "label": p.label, "description": p.description,
         "base_url": p.base_url, "default_model": p.default_model,
         "needs_api_key": p.needs_api_key, "default_choice": p.default_choice,
         "notes": p.notes}
        for p in ls.PRESETS
    ]


def _provider_summary(name: str) -> dict:
    active_roles = [role for role, var in ls.PROVIDER_ROLE_VARS.items()
                    if providers.role_name(var) == name]
    try:
        p = providers.resolve(name)
        from agent.llm import resolve_api_compat
        profile = resolve_api_compat(name, p.model)
        return {"name": name, "base_url": p.base_url, "model": p.model or None,
                "key_set": bool(p.api_key), "roles": active_roles,
                "usable": True, "error": None,
                # How hard its models are asked to think, and what replies
                # have shown so far.
                "thinking": providers.thinking_level(name) or "auto",
                "reasoning_observed": profile.reasoning_observed,
                "thinking_control": profile.thinking_control}
    except providers.UnknownProvider as exc:
        return {"name": name, "base_url": None, "model": None,
                "key_set": False, "roles": active_roles,
                "usable": False, "error": str(exc)}


def model_overrides() -> list[dict]:
    """Role model overrides in .env that outrank the provider assignment.

    Each entry says which role is affected, the variable holding it, the model
    it forces and the provider model it is displacing — enough for the page to
    explain what a run will actually use.
    """
    env = envfile.read_values(_env_path())
    out: list[dict] = []
    for role, var in ls.shadowing_model_vars(env).items():
        name = providers.role_name(ls.PROVIDER_ROLE_VARS[role])
        try:
            provider_model = providers.resolve(name).model if name else ""
        except providers.UnknownProvider:
            provider_model = ""
        out.append({"role": role, "var": var,
                    "model": (env.get(var) or "").strip(),
                    "provider": name or None,
                    "provider_model": provider_model or None})
    return out


def list_providers() -> dict:
    # llmhub always resolves (its base URL falls back to a hardcoded
    # default — see core/llmhub.py) so it can't be un-declared like every
    # other provider. When it isn't actually in use (no key, no roles
    # assigned) hide it instead — same visible effect as deleting an unused
    # row, without pretending the always-available default went away.
    summaries = [_provider_summary(n) for n in providers.names()]
    summaries = [p for p in summaries if not (
        p["name"] == providers.DEFAULT_NAME and not p["key_set"] and not p["roles"])]
    return {
        "presets": presets(),
        "providers": summaries,
        "malformed": providers.malformed(),
        "roles": list(ls.PROVIDER_ROLE_VARS.keys()),
        # A role whose model override is set does not run the model shown
        # against its provider. Saving that provider clears the override, so
        # this only ever reports one written by hand or by an older Atlas.
        "model_overrides": model_overrides(),
        # Single source of truth for the "not a model id" check — the JS
        # reads this instead of hardcoding its own copy of the role names.
        "identity_model_ids": sorted(ls.IDENTITY_MODEL_IDS),
    }


def probe(base_url: str, api_key: str, auth_header: str = "",
          auth_prefix: Optional[str] = None, model: str = "",
          name: str = "") -> dict:
    """Test connection: which models the provider lists and, with a model id,
    what that model can do (answer, call tools, think, take a level).

    The capability report is what the role checkboxes and the Thinking
    setting are chosen against. A failed report never fails the connection
    test: the provider is still reachable and still saveable.
    """
    model = (model or "").strip()
    if not model:
        result = ls.probe(base_url, api_key, auth_header=auth_header,
                          auth_prefix=auth_prefix)
        return {"ok": result.ok, "status": result.status,
                "models": result.models, "error": result.error}
    caps = ls.probe_capabilities(base_url, api_key, model,
                                 auth_header=auth_header, auth_prefix=auth_prefix,
                                 provider_name=name)
    return {"ok": caps.ok or caps.reachable, "status": caps.status,
            "models": caps.models, "error": caps.error,
            "capabilities": caps.to_dict()}


def save_provider(data: dict[str, Any]) -> dict:
    """data: {preset_id, name, base_url, model, auth_header, auth_prefix,
    roles: [...], api_key (optional, ""=unchanged), store_key_in:
    "keyring"|"env"|"skip", skip_probe (bool)}.

    Mirrors cmd_provider_setup's ordering: build the update set, probe
    unless explicitly skipped (refusing to save on a failed probe, exactly
    like the CLI wizard), then write .env, then the API key separately.
    """
    name = str(data.get("name") or "").strip()
    if err := ls.validate_name(name):
        raise ConfigError(err)
    base_url = str(data.get("base_url") or "").strip()
    roles = tuple(r for r in (data.get("roles") or []) if r in ls.PROVIDER_ROLE_VARS)
    api_key = str(data.get("api_key") or "")
    auth_header = str(data.get("auth_header") or "") or None
    # Omitted or blank AUTH_PREFIX means "use the provider default" (Bearer
    # on Authorization). Do not write AUTH_PREFIX= — an empty assignment
    # used to strip Bearer and OpenRouter answered 401.
    raw_prefix = data.get("auth_prefix")
    auth_prefix = None if raw_prefix is None or str(raw_prefix) == "" else str(raw_prefix)
    model = str(data.get("model") or "").strip()
    thinking = str(data.get("thinking") or "auto").strip().lower()
    if ls.is_identity_model_id(model):
        raise ConfigError(
            f"model {model!r} looks like a dashboard role or username, not a "
            f"model id. Use the provider catalogue id (e.g. openai/gpt-4o-mini "
            f"on OpenRouter, GLM-5.2 on the Telekom LLM Hub).")

    losing = ls.roles_losing_coverage(name, roles)
    if losing and not data.get("force"):
        # Only an existing provider holds roles, so this save edits it.
        raise ConfigError(
            f"{name!r} is an existing provider and saving replaces its "
            f"settings. Saving it without these roles would leave them with no "
            f"provider at all: {', '.join(losing)}. To add another model, "
            f"save it under a new name; to move the roles, assign them to a "
            f"different provider first, or pass force=true to confirm anyway.")

    try:
        choice = ls.SetupChoice(
            preset_id=str(data.get("preset_id") or "custom"), name=name,
            base_url=base_url, model=model,
            auth_header=auth_header or "", auth_prefix=auth_prefix,
            roles=roles, thinking=thinking)
        updates = ls.register_provider_updates(choice)
        # Back to auto clears the pinned level the file may hold.
        if thinking == "auto":
            updates[providers.thinking_var(name)] = ""
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    updates.update(ls.declared_providers_update(providers.declared(), name))
    # Read the overrides from the file, not this process's environment: the
    # dashboard may have started before one was added, and it is the file the
    # run will load.
    updates.update(ls.role_updates(name, roles,
                                   envfile.read_values(_env_path())))

    probe_result = None
    if api_key and not data.get("skip_probe"):
        probe_result = probe(base_url, api_key, auth_header or "", auth_prefix)
        if not probe_result["ok"]:
            raise ConfigError(
                f"provider did not respond correctly at {base_url} "
                f"({probe_result['error'] or 'unreachable'}) — save aborted, "
                f"nothing was written. Pass skip_probe to save anyway.")
        listed = probe_result.get("models") or []
        if model and listed and model not in listed:
            from core.model_context import match_model_entry
            hit = match_model_entry(
                [{"id": mid} for mid in listed if mid], model)
            if hit is None:
                raise ConfigError(
                    f"model {model!r} is not available from this provider "
                    f"({len(listed)} models listed). Pick an id from the "
                    f"Test connection result, or pass skip_probe to save "
                    f"anyway.")

    with envfile.lock():
        env_path = _env_path()
        envfile.set_values(env_path, updates)
        for key, value in updates.items():
            os.environ[key] = value  # this process's own env, for immediate effect

        key_result = {"stored": "skip"}
        if api_key:
            key_var = ls.key_env_var(name)
            key_result = envfile.save_secret_value(
                _REPO_ROOT, env_path, key_var, api_key,
                str(data.get("store_key_in") or "env"))

    return {"success": True, "updates": updates, "probe": probe_result,
           "api_key": key_result}


def assign_role(role: str, name: str) -> dict:
    """Point one role at provider ``name``, or turn the role off with "".

    save_provider sets roles only as part of saving a whole provider; the
    Settings page's Roles in a run table changes one role at a time, and
    every other role keeps its provider. Assigning a role clears that role's
    model override, as save_provider does, because the override is read
    before the provider's model: the assignment would be shown and not
    followed. The analyst cannot be turned off, since a run cannot start
    without it.
    """
    role = (role or "").strip()
    name = (name or "").strip()
    var = ls.PROVIDER_ROLE_VARS.get(role)
    if var is None:
        raise ConfigError(f"no such role: {role!r}")
    if not name and role == "analyst":
        raise ConfigError("the analyst role needs a provider: a run cannot start without one")
    if name and name not in providers.names():
        raise ConfigError(f"no such provider: {name!r}")

    updates = {var: name}
    with envfile.lock():
        env_path = _env_path()
        if name:
            # Read from the file, not this process's environment: an override
            # added by hand after the dashboard started is still in force.
            shadowing = ls.shadowing_model_vars(envfile.read_values(env_path), (role,))
            updates.update({model_var: "" for model_var in shadowing.values()})
        envfile.set_values(env_path, updates)
        for key, value in updates.items():
            os.environ[key] = value  # this process's own env, for immediate effect
    return {"success": True, "role": role, "provider": name, "updates": updates}


def delete_provider(name: str) -> dict:
    """Un-declares `name` from ATLAS_PROVIDERS and clears any role pointing
    at it. Refuses (same rule as save_provider) if that would leave a role
    with no provider at all, and refuses to remove the built-in default."""
    name = (name or "").strip()
    if not name:
        raise ConfigError("a provider name is required")
    if name == providers.DEFAULT_NAME:
        raise ConfigError("the built-in Telekom LLM Hub provider can't be removed")
    declared = providers.declared()
    if name not in declared:
        raise ConfigError(f"no such provider: {name!r}")

    losing = ls.roles_losing_coverage(name, ())
    if losing:
        raise ConfigError(
            f"Removing {name!r} would leave these roles with no provider at "
            f"all: {', '.join(losing)}. Assign them to a different provider "
            f"first.")

    updates = ls.role_updates(name, ())
    updates.update(ls.undeclare_provider_update(declared, name))

    with envfile.lock():
        env_path = _env_path()
        envfile.set_values(env_path, updates)
        for key, value in updates.items():
            os.environ[key] = value

    return {"success": True, "removed": name}
