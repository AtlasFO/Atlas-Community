"""Provider profiles: what Atlas knows about a provider type, kept as data.

Shipped profiles live in ``provider_profiles/<id>.toml``; the operator's own
in ``provider_profiles.local/`` beside them (git-ignored) or in the folder
``ATLAS_PROVIDER_PROFILES_DIR`` names. A user file deep-merges over the
shipped file of the same id: tables merge key by key, values and arrays
replace, so one changed value keeps every later shipped fix; a new id adds a
profile. Each merged profile is checked against ``provider_profiles/schema.json``
and the rules below that a schema cannot state. A file that fails is not
used: an instance bound to its id is unusable and says why, and is never
served by the shipped file in its place. Profiles are read from these two
folders only, never from a case folder, and once per process, so a run never
sees a file edited after it started; the dashboard reloads on request.

A configured provider (an instance in ``.env``) binds to a profile by
``ATLAS_PROVIDER_<NAME>_PRESET``, else by its own name compared without case,
else to ``custom``. Profiles are data only: the wire formats (dialects) and
auth schemes they choose from stay code.
"""
from __future__ import annotations

import difflib
import fnmatch
import hashlib
import ipaddress
import json
import os
import sys
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[1]
SHIPPED_DIR = REPO / "provider_profiles"
USER_DIR = REPO / "provider_profiles.local"
DIR_ENV = "ATLAS_PROVIDER_PROFILES_DIR"
# The hash of the profiles a run started with; a child process compares.
HASH_ENV = "ATLAS_PROVIDER_PROFILES_HASH"
FALLBACK = "custom"
DIALECTS = ("chat", "responses", "messages")
# Headers that carry credentials or framing: the key travels only through
# [auth], and HTTP itself sets the rest. Universal HTTP knowledge.
_RESERVED_HEADERS = frozenset({"authorization", "proxy-authorization", "x-api-key", "api-key",
                               "cookie", "host", "content-length", "content-type",
                               "transfer-encoding", "connection", "te", "upgrade"})


class ProfileError(ValueError):
    """A profile that cannot be used, or an instance bound to none."""


@dataclass(frozen=True)
class Profile:
    id: str
    label: str
    description: str = ""
    notes: str = ""
    evidence: str = ""
    order: int = 0
    dialect: str = "chat"
    implicit: bool = False
    needs_api_key: bool = True
    disabled: bool = False
    base_url: str = ""
    default_model: str = ""
    # How the model list pages: "none", or "after_id" (limit, after_id,
    # has_more and last_id, as Anthropic's list pages).
    models_paging: str = "none"
    auth_header: str = ""
    auth_prefix: str | None = None
    env: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    send_temperature: bool = True
    tool_choice_rejected: tuple[str, ...] = ()
    # Whether the provider's input-tokens-per-minute limit counts the tokens
    # read from its prompt cache; Atlas's own pacing counts what it counts.
    rate_limit_counts_cache_reads: bool = True
    # How many tool schemas one request may carry, where the provider says
    # (None: Atlas's common cap applies).
    max_tools: int | None = None
    control: str = "reasoning_effort"
    levels: dict = field(default_factory=dict)
    echo_fields: tuple[str, ...] = ()
    # Model rules: a glob on the model id -> {"request": {...}, "reasoning": {...}}.
    models: dict = field(default_factory=dict)
    source: str = "shipped"          # shipped | user | merged
    files: tuple[str, ...] = ()

    @classmethod
    def from_data(cls, data: dict, source: str, files: tuple[str, ...]) -> "Profile":
        conn, auth = data.get("connection") or {}, data.get("auth") or {}
        reasoning, request = data.get("reasoning") or {}, data.get("request") or {}
        return cls(
            id=data["id"], label=data["label"], description=data.get("description", ""),
            notes=data.get("notes", ""), evidence=data.get("evidence", ""), order=data.get("order", 0),
            dialect=data.get("dialect", "chat"), implicit=data.get("implicit", False),
            needs_api_key=data.get("needs_api_key", True), disabled=data.get("disabled", False),
            base_url=conn.get("base_url", ""), default_model=conn.get("default_model", ""),
            models_paging=conn.get("models_paging", "none"),
            auth_header=auth.get("header", ""), auth_prefix=auth.get("prefix"),
            env=dict(data.get("env") or {}), headers=dict(data.get("headers") or {}),
            send_temperature=request.get("temperature", True),
            tool_choice_rejected=tuple(request.get("tool_choice_rejected") or ()),
            rate_limit_counts_cache_reads=request.get("rate_limit_counts_cache_reads", True),
            max_tools=request.get("max_tools"),
            control=reasoning.get("control", "reasoning_effort"), levels=dict(reasoning.get("levels") or {}),
            echo_fields=tuple(reasoning.get("echo_fields") or ()), models=dict(data.get("models") or {}),
            source=source, files=files)

    def for_model(self, model: str) -> "Profile":
        """This profile with the rules that match ``model`` applied, least
        specific first (specificity: the characters of a glob that are not
        wildcards); an exact id wins. A rule's levels change or add to the
        map they apply to, key by key, as a user file's tables do."""
        rules = sorted((glob for glob in self.models if fnmatch.fnmatchcase(model or "", glob)),
                       key=lambda glob: len(glob.replace("*", "").replace("?", "")))
        out = self
        for glob in rules:
            request, reasoning = self.models[glob].get("request") or {}, self.models[glob].get("reasoning") or {}
            out = replace(out, send_temperature=request.get("temperature", out.send_temperature),
                          tool_choice_rejected=tuple(request.get("tool_choice_rejected", out.tool_choice_rejected)),
                          rate_limit_counts_cache_reads=request.get("rate_limit_counts_cache_reads",
                                                                    out.rate_limit_counts_cache_reads),
                          max_tools=request.get("max_tools", out.max_tools),
                          control=reasoning.get("control", out.control),
                          levels={**out.levels, **(reasoning.get("levels") or {})},
                          echo_fields=tuple(reasoning.get("echo_fields", out.echo_fields)))
        return out

    def request_shape(self, model: str = "") -> dict:
        """The fields this profile seeds a request shape with for ``model``,
        as keyword arguments of agent.llm.ApiCompatProfile; {} when it has
        nothing to say. A Messages profile always needs the explicit cap: the
        API requires max_tokens, and the cap the ladder knows is then the cap
        on the wire."""
        p = self.for_model(model)
        out: dict = {}
        if p.control != "reasoning_effort":
            out["thinking_control"] = p.control
        if p.levels:
            out["effort_values"] = tuple(dict.fromkeys(p.levels.values()))
        if p.echo_fields:
            out["echo_fields"] = p.echo_fields
        if not p.send_temperature:
            out["send_temperature"] = False
        if p.tool_choice_rejected:
            out["tool_choice_rejected"] = p.tool_choice_rejected
        if self.dialect == "messages":
            out["needs_explicit_cap"] = True
        return out

    def level_map(self, model: str = "") -> dict:
        """Atlas level -> the value sent for it, for the levels that differ."""
        return {k: v for k, v in self.for_model(model).levels.items() if k != v}

    def seed(self, model: str = "") -> str:
        """A short hash of what this profile seeds a request with for
        ``model``: a shape learned under another seed is not reused."""
        shape = {"dialect": self.dialect, **self.request_shape(model), "levels": self.for_model(model).levels}
        return hashlib.sha256(json.dumps(shape, sort_keys=True, default=list).encode()).hexdigest()[:12]


@dataclass(frozen=True)
class Catalog:
    profiles: dict          # id -> Profile, the usable ones
    errors: dict            # id -> why the profile of that id is unusable
    shipped_dir: Path
    user_dir: Path
    fingerprint: str
    ignored: dict = field(default_factory=dict)   # user file -> why it is not read


_catalog: Catalog | None = None


def user_dir() -> Path:
    """The folder of the user's own profiles. ``~`` is expanded, and a
    relative setting is taken under the Atlas folder, never the working
    directory, which can be a case folder."""
    folder = Path(os.environ.get(DIR_ENV) or USER_DIR).expanduser()
    return folder if folder.is_absolute() else REPO / folder


def load(*, reload: bool = False) -> Catalog:
    """Every profile, read once per process unless ``reload`` (or the user
    folder setting changed, as when a .env is loaded after a first read)."""
    global _catalog
    if _catalog is None or reload or _catalog.user_dir != user_dir():
        _catalog = _read(SHIPPED_DIR, user_dir())
        for why in _catalog.ignored.values():
            print(f"[atlas] {why}", file=sys.stderr)
        if (drift := child_drift()):
            print(f"[atlas] {drift}", file=sys.stderr)
    return _catalog


def _read(shipped_dir: Path, user: Path) -> Catalog:
    schema = json.loads((shipped_dir / "schema.json").read_text(encoding="utf-8"))
    shipped = {p.stem: p for p in sorted(shipped_dir.glob("*.toml"))}
    local = {p.stem: p for p in sorted(user.glob("*.toml"))} if user.is_dir() else {}
    profiles, errors, ignored = {}, {}, {}
    if FALLBACK in local:
        # Every provider no other profile claims binds to the fallback: a
        # user file there would decide for all of them, so it is not read.
        path = local.pop(FALLBACK)
        ignored[_show(path)] = (f"{_show(path)} is not read: the fallback profile {FALLBACK!r} cannot be "
                                f"changed by a user file; give your provider a profile of its own")
    for pid in sorted(set(shipped) | set(local)):
        try:
            profiles[pid] = _build(pid, shipped.get(pid), local.get(pid), schema)
        except ProfileError as exc:
            errors[pid] = str(exc)
    digest = hashlib.sha256(json.dumps(
        {"profiles": {k: repr(v.__dict__) for k, v in sorted(profiles.items())},
         "errors": dict(sorted(errors.items()))}, sort_keys=True).encode()).hexdigest()[:16]
    return Catalog(profiles, errors, shipped_dir, user, digest, ignored)


def _parse(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ProfileError(f"{_show(path)}: not readable as TOML: {exc}") from None


def _show(path: Path) -> str:
    try:
        return str(path.relative_to(REPO))
    except ValueError:
        return str(path)


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for key, value in over.items():
        out[key] = _merge(out[key], value) if isinstance(value, dict) and isinstance(out.get(key), dict) else value
    return out


def _build(pid: str, shipped: Path | None, local: Path | None, schema: dict) -> Profile:
    data = _parse(shipped) if shipped else {}
    if shipped and data.get("id") != pid:
        raise ProfileError(f"{_show(shipped)}: id {data.get('id')!r} is not the file name {pid!r}")
    where = _show(local or shipped)
    if local:
        over = _parse(local)
        if over.get("id") != pid:
            raise ProfileError(f"{where}: id {over.get('id')!r} is not the file name {pid!r}")
        for key in ("env", "implicit"):
            if key in over:
                raise ProfileError(f"{where}: {key} is allowed in shipped profiles only")
        data = _merge(data, over)
    _check_schema(data, schema, where)
    _check_rules(data, where)
    source = "merged" if shipped and local else "user" if local else "shipped"
    return Profile.from_data(data, source, tuple(_show(p) for p in (shipped, local) if p))


def _check_schema(data: dict, schema: dict, where: str) -> None:
    import jsonschema
    validator = jsonschema.Draft202012Validator(schema)
    error = next(iter(sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))), None)
    if error is None:
        return
    path = ".".join(str(p) for p in error.absolute_path) or "(top level)"
    message = error.message
    if error.validator == "additionalProperties":
        allowed = list((error.schema.get("properties") or {}))
        unknown = sorted(set(error.instance) - set(allowed))
        hints = [f"{k!r} (did you mean {m[0]!r}?)" if (m := difflib.get_close_matches(k, allowed, 1)) else repr(k)
                 for k in unknown]
        message = f"unknown key {', '.join(hints)}; known: {', '.join(allowed)}"
    elif error.validator == "enum" and path == "dialect":
        message = (f"dialect {error.instance!r} is not one Atlas speaks ({', '.join(DIALECTS)}). A vendor with an "
                   f"OpenAI-compatible endpoint uses dialect = \"chat\"; another wire format needs a dialect in "
                   f"Atlas's code, or a gateway that speaks one of these")
    raise ProfileError(f"{where}: {path}: {message}")


def _local_host(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (ip.is_loopback or ip.is_private) and not ip.is_link_local


def _check_rules(data: dict, where: str) -> None:
    """What the schema cannot state."""
    base_url = (data.get("connection") or {}).get("base_url", "")
    if base_url:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ProfileError(f"{where}: connection.base_url: {base_url!r} is not an http(s) URL")
        if parts.scheme == "http" and not _local_host(parts.hostname):
            raise ProfileError(f"{where}: connection.base_url: plain http is allowed for a loopback or "
                               f"private address only; use https for {parts.hostname!r}")
    auth_header = ((data.get("auth") or {}).get("header") or "").lower()
    for name, value in (data.get("headers") or {}).items():
        if name.lower() in _RESERVED_HEADERS or name.lower() == auth_header:
            raise ProfileError(f"{where}: headers.{name}: credentials and framing headers cannot be set here; "
                               f"the key goes through [auth]")
        if "\r" in value or "\n" in value:
            raise ProfileError(f"{where}: headers.{name}: a header value holds no line break")
    dialect = data.get("dialect", "chat")
    spellings = {"chat": ("reasoning_effort", "reasoning_object", "thinking_type", "enable_thinking", "none"),
                 "responses": ("reasoning_effort", "none"), "messages": ("output_config", "none")}[dialect]
    for where_key, table in [("reasoning", data.get("reasoning") or {})] + [
            (f'models."{glob}".reasoning', (rule or {}).get("reasoning") or {})
            for glob, rule in (data.get("models") or {}).items()]:
        control = table.get("control")
        if control is not None and control not in spellings:
            raise ProfileError(f"{where}: {where_key}.control: {control!r} is not how the {dialect} dialect "
                               f"spells a level ({', '.join(spellings)})")
    if dialect == "messages" and (data.get("reasoning") or {}).get("control", "reasoning_effort") == "reasoning_effort":
        raise ProfileError(f"{where}: reasoning.control: the messages dialect spells a level as "
                           f"output_config (or none)")
    env = data.get("env") or {}
    if data.get("implicit") and not all(env.get(k) for k in ("base_url", "model", "api_key")):
        raise ProfileError(f"{where}: env: an implicit profile names its base_url, model and api_key variables")


# ── lookups ──────────────────────────────────────────────────────────────

def get(profile_id: str) -> Profile:
    """The usable profile ``profile_id``; ProfileError says why there is none."""
    catalog = load()
    pid = (profile_id or "").strip().casefold()
    if pid in catalog.errors:
        raise ProfileError(catalog.errors[pid])
    profile = catalog.profiles.get(pid)
    if profile is None:
        raise ProfileError(f"no provider profile {profile_id!r}; known: {', '.join(sorted(catalog.profiles))}")
    if profile.disabled:
        raise ProfileError(f"provider profile {pid!r} is disabled ({', '.join(profile.files)})")
    return profile


def menu() -> list[Profile]:
    """The profiles a setup menu offers, in menu order."""
    return sorted((p for p in load().profiles.values() if not p.disabled), key=lambda p: (p.order, p.id))


def implicit(name: str) -> Profile | None:
    """The implicit profile named exactly ``name`` (an instance of its own), else None."""
    profile = load().profiles.get((name or "").strip())
    return profile if profile is not None and profile.implicit and not profile.disabled else None


def implicit_ids() -> list[str]:
    return [p.id for p in menu() if p.implicit]


def instance_var(name: str, suffix: str) -> str:
    """The variable carrying ``suffix`` (BASE_URL, MODEL, API_KEY, THINKING,
    API) for instance ``name``: an implicit profile's own [env] names, else
    ATLAS_PROVIDER_<NAME>_<SUFFIX>."""
    profile = implicit(name)
    if profile is not None:
        named = profile.env.get(suffix.lower())
        if named:
            return named[0] if isinstance(named, list) else named
    return f"ATLAS_PROVIDER_{instance_stem(name)}_{suffix}"


def instance_stem(name: str) -> str:
    """The part of instance ``name``'s variables that names it: upper case,
    "-" as "_". Two names with one stem share every variable, so the
    providers they name cannot both exist (core.providers.colliding_name)."""
    return name.strip().upper().replace("-", "_")


def bind(name: str, base_url: str = "") -> tuple[Profile, str]:
    """The profile instance ``name`` uses and the rule that chose it: the one
    its _PRESET variable names ("preset"), else the one named like the
    instance ("name"), else the fallback ("fallback"). A _PRESET that names no
    profile, or a chosen profile that is unusable, raises ProfileError. A
    profile whose dialect is not chat binds by name only when the instance
    points at that profile's own host, so a gateway named like a vendor
    stays on Chat Completions."""
    catalog = load()
    preset_var = instance_var(name, "PRESET")
    preset = (os.environ.get(preset_var) or "").strip()
    if preset:
        if preset.casefold() not in catalog.profiles and preset.casefold() not in catalog.errors:
            raise ProfileError(f"{preset_var}={preset!r} names no provider profile; known: "
                               f"{', '.join(sorted(catalog.profiles))}")
        return get(preset), "preset"
    pid = (name or "").strip().casefold()
    if pid in catalog.profiles or pid in catalog.errors:
        profile = get(pid)
        if profile.dialect == "chat" or _host(base_url) == _host(profile.base_url):
            return profile, "name"
        return get(FALLBACK), "fallback (named like a non-chat profile at another host)"
    return get(FALLBACK), "fallback"


def _host(url: str) -> str:
    return (urlsplit(url or "").hostname or "").casefold()


def managed_key_vars() -> list[str]:
    """The key variables the shipped implicit profiles name, for the keyring loader."""
    return [var for p in load().profiles.values() if p.implicit for var in p.env.get("api_key", [])]


def pin_for_children() -> str:
    """Record the profiles this process runs with, so a child process can
    tell when it reads a file edited after the run started."""
    fingerprint = load().fingerprint
    os.environ[HASH_ENV] = fingerprint
    return fingerprint


def child_drift() -> str:
    """A warning when this process reads other profiles than the run that
    started it, else ""."""
    pinned = os.environ.get(HASH_ENV) or ""
    current = load().fingerprint
    if pinned and pinned != current:
        return (f"provider profiles changed since the run started ({pinned} -> {current}); "
                f"this process uses the edited files")
    return ""
