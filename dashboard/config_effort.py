"""Reading and writing the per-role reasoning level from the dashboard.

The vocabulary — which roles exist, which levels they take, what each role
does — lives in ``core.effort``; this module only moves it between the .env
file and the Settings page. ``core.envfile`` owns the write lock for .env, so
a save here cannot interleave with one from the provider form.

It also reports whether the analyst's own endpoint pins a value of its own.
Some endpoints require a reasoning model to stop reasoning while Atlas's
function tools are on the request, and there the configured level is not
applied. That is worth saying on the page rather than leaving a user to
wonder why a setting they saved changed nothing.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from core import effort, envfile, providers

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _env_path() -> Path:
    path = envfile.resolve(_REPO_ROOT)
    if not path.is_file():
        raise FileNotFoundError(
            f"no .env at {path} — create it first (cp .env.example .env)")
    return path


def _analyst_pin() -> dict:
    """Whether the analyst's endpoint pins a reasoning level of its own.

    Answered from the compat profile Atlas already keeps for that
    provider+model pair, which is where such a requirement is recorded — by a
    400 the endpoint returned, or by the hint for a model family documented to
    need it. Never probes: the page must render without sending a request.
    """
    unknown = {"pinned": False, "provider": "", "model": ""}
    try:
        name = providers.role_name("ATLAS_AGENT_PROVIDER")
        if not name:
            return unknown
        provider = providers.resolve(name)
        model = (os.environ.get("ATLAS_AGENT_MODEL") or provider.model or "").strip()
        if not model:
            return {**unknown, "provider": name}
        from agent.llm import resolve_api_compat
        profile = resolve_api_compat(name, model)
        return {
            "pinned": profile.reasoning_effort == "none",
            "provider": name,
            "model": model,
        }
    except Exception:
        # A provider that will not resolve is the LLM card's problem to
        # report, not this one's; the levels stay readable and settable.
        return unknown


def settings() -> dict:
    """Every settable role with its configured and effective level."""
    values = envfile.read_values(_env_path())
    return {
        "values": list(effort.VALUES),
        "roles": effort.settings(values),
        "analyst_endpoint": _analyst_pin(),
    }


def save(data: dict[str, Any]) -> dict:
    """Write the levels in ``data['roles']`` ({role: level}) to .env.

    Validation happens before the lock is taken, so a rejected value leaves
    the file untouched rather than half-written. The process environment is
    updated alongside the file for the same reason the provider form does it:
    a run started from this process must see what was just saved.
    """
    updates = effort.updates((data or {}).get("roles") or {})
    if not updates:
        return {"success": True, "updates": {}, **settings()}
    with envfile.lock():
        path = _env_path()
        envfile.set_values(path, updates)
        for key, value in updates.items():
            os.environ[key] = value
    return {"success": True, "updates": updates, **settings()}
