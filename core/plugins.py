"""Atlas addon registry — discovery, registration, and manifest metadata.

Third-party and first-party addons live under ``plugins/<name>/`` and expose
a ``register(mcp)`` entry point (write it by hand, or subclass
``core.addons.Addon`` and get it for free — see docs/addons.md).
``server.py`` calls ``register_plugins(mcp)`` once after core middleware is
attached — the only stable integration point.

Disable individual addons via ``ATLAS_PLUGINS_DISABLED=timeline_builder,...``.
Disable all addons via ``ATLAS_PLUGINS=0``.

An addon may ship an ``addon.yaml`` next to its ``plugin.py`` (name, version,
description, author, min_atlas_version) — entirely optional, read by
``read_manifest()``/``list_addons()`` for ``atlas addon list``. Nothing here
enforces it; a manifest-less addon works exactly as before.
"""
from __future__ import annotations

import importlib
import os
import pkgutil
import re
import sys
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Protocol, runtime_checkable

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PLUGINS_PKG = "plugins"
ATLAS_VERSION = "1.0.1"

# Matches agent/cli.py's cmd_addon_create — an addon name is a Python
# package name (plugins/<name>/ becomes `import plugins.<name>`).
_NAME_RE = re.compile(r"[a-z][a-z0-9_]*")


class PluginError(Exception):
    """Raised by install_from_zip for a bad name, a name collision, or a
    zip whose members would land outside plugins/<name>/. Every other
    function in this module is deliberately fail-open (a broken *existing*
    addon must never take the server down) — installing a *new* one is the
    one operation that should refuse loudly instead of silently doing
    something unsafe."""


@runtime_checkable
class AtlasPlugin(Protocol):
    """Investigation plugin — registers middleware, tools, or hooks on the MCP server."""

    name: str

    def register(self, mcp) -> None:
        """Attach to the shared FastMCP instance (idempotent)."""


def _plugins_enabled() -> bool:
    flag = (os.environ.get("ATLAS_PLUGINS") or "1").strip().lower()
    return flag not in ("0", "false", "no", "off")


def _disabled_names() -> frozenset[str]:
    raw = os.environ.get("ATLAS_PLUGINS_DISABLED") or ""
    return frozenset(n.strip() for n in raw.split(",") if n.strip())


def discover_plugin_modules() -> list[str]:
    """Return import paths for subpackages under ``plugins/`` with ``register``."""
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))
    try:
        pkg = importlib.import_module(_PLUGINS_PKG)
    except ImportError:
        return []
    if not hasattr(pkg, "__path__"):
        return []
    out: list[str] = []
    for mod in pkgutil.iter_modules(pkg.__path__):
        if mod.name.startswith("_"):
            continue
        full = f"{_PLUGINS_PKG}.{mod.name}"
        try:
            m = importlib.import_module(full)
        except Exception as exc:  # noqa: BLE001 — one bad plugin must not break server
            print(f"[Atlas WARN] plugin {full} failed to import: {exc!r}",
                  file=sys.stderr)
            continue
        if callable(getattr(m, "register", None)):
            out.append(full)
    return sorted(out)


def read_manifest(name: str) -> dict | None:
    """Read plugins/<name>/addon.yaml, or None if absent/unreadable.

    Fields are all optional: version, description, author,
    min_atlas_version. A manifest is metadata only — never required for an
    addon to load or register.
    """
    path = _REPO_ROOT / _PLUGINS_PKG / name / "addon.yaml"
    if not path.is_file():
        return None
    try:
        import yaml
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception as exc:  # noqa: BLE001 — a bad manifest must not break discovery
        print(f"[Atlas WARN] addon.yaml for {name!r} unreadable: {exc!r}",
              file=sys.stderr)
        return None


def _version_tuple(v: str) -> tuple[int, ...]:
    parts = []
    for p in str(v or "").split("."):
        digits = "".join(ch for ch in p if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) or (0,)


def compatible(manifest: dict | None) -> bool:
    """True unless the manifest declares a min_atlas_version we don't meet.

    Warn-only in practice (see list_addons/register_plugins) — an
    incompatible addon is still attempted, matching the fail-open posture
    everything else in this module already has.
    """
    if not manifest:
        return True
    required = manifest.get("min_atlas_version")
    if not required:
        return True
    return _version_tuple(ATLAS_VERSION) >= _version_tuple(required)


def _addon_classes(mod, event: str) -> list[type]:
    """Addon subclasses in `mod` hooking `event`.

    Looked for in the package namespace first — an addon that exports its
    class there is found whatever its file layout — then in the ``plugin``
    submodule, which is where ``atlas addon create`` puts it and where an
    addon that only exports ``register`` keeps it.
    """
    from core.addons import declares_event
    return _addon_classes_where(mod, lambda cls: declares_event(cls, event))


def _addon_classes_where(mod, keep) -> list[type]:
    """Addon subclasses in `mod` for which `keep(cls)` holds, found as
    ``_addon_classes`` describes."""
    from core.addons.sdk import Addon

    def _scan(namespace) -> list[type]:
        return [obj for obj in vars(namespace).values()
                if isinstance(obj, type) and issubclass(obj, Addon)
                and obj is not Addon and keep(obj)]

    found = _scan(mod)
    if found:
        return found
    try:
        return _scan(importlib.import_module(f"{mod.__name__}.plugin"))
    except Exception:  # noqa: BLE001 — no plugin submodule is not an error
        return []


def is_enabled(name: str) -> bool:
    """Whether addon `name` is active right now.

    Public because "is this addon on?" is asked outside registration too —
    the dashboard gates a download on it, and event dispatch below skips a
    disabled addon. Reading the two switches by hand in each caller is how
    an addon ends up half-disabled: its tools gone, its side effects still
    running.
    """
    return _plugins_enabled() and (name or "").strip() not in _disabled_names()


def intel_readers() -> dict[str, dict]:
    """Threat-context readers that enabled addons declare (``@intel_reader``),
    by name: ``{"read": method, "suffixes": (...), "addon": name}``. The
    first addon to claim a name keeps it; a broken addon is skipped."""
    import inspect

    from core.addons.sdk import _bound_marked

    def declares(cls: type) -> bool:
        return any(hasattr(a, "_atlas_intel_reader") for _, a in inspect.getmembers(cls))

    out: dict[str, dict] = {}
    for mod_path in discover_plugin_modules():
        name = mod_path.rsplit(".", 1)[-1]
        if not is_enabled(name):
            continue
        try:
            mod = importlib.import_module(mod_path)
        except Exception:  # noqa: BLE001
            continue
        for cls in _addon_classes_where(mod, declares):
            try:
                inst = cls()
            except Exception:  # noqa: BLE001
                continue
            for bound in _bound_marked(inst, "_atlas_intel_reader"):
                meta = bound.method._atlas_intel_reader
                out.setdefault(meta["name"], {"read": bound.method, "suffixes": meta["suffixes"],
                                              "addon": name})
    return out


def addons_for_event(event: str) -> list[dict]:
    """Addons declaring `event`, each with whether it is enabled.

    Answers "would anything produce this?" without running a hook — for a
    report that has to explain why an optional artifact is absent.
    """
    out: list[dict] = []
    for mod_path in discover_plugin_modules():
        name = mod_path.rsplit(".", 1)[-1]
        try:
            mod = importlib.import_module(mod_path)
        except Exception:  # noqa: BLE001 — a broken addon is not a listing error
            continue
        if _addon_classes(mod, event):
            out.append({"addon": name, "enabled": is_enabled(name)})
    return out


def dispatch_event(event: str, **payload) -> list[dict]:
    """Deliver `event` to every enabled addon hooking it; report the rest.

    Returns one entry per addon that declares the event, whichever way it
    went: ``status`` is ``ok`` (with the hook's ``result``), ``failed``
    (with ``error``), or ``disabled`` — so an addon that is switched off is
    visible as switched off rather than as nothing at all. Never raises:
    core calls this at moments (a report has just been written) where an
    addon's problem must not become the run's problem.
    """
    from core.addons import hooks_for
    from core.addons.sdk import EVENTS

    if event not in EVENTS:
        raise ValueError(f"unknown addon event {event!r} — one of {sorted(EVENTS)}")

    out: list[dict] = []
    for mod_path in discover_plugin_modules():
        name = mod_path.rsplit(".", 1)[-1]
        try:
            mod = importlib.import_module(mod_path)
        except Exception as exc:  # noqa: BLE001
            out.append({"addon": name, "event": event, "status": "failed",
                        "error": f"import failed: {exc!r}"})
            continue
        classes = _addon_classes(mod, event)
        if not classes:
            continue
        if not is_enabled(name):
            out.append({"addon": name, "event": event, "status": "disabled"})
            continue
        for addon_cls in classes:
            for bound in hooks_for(addon_cls(), event):
                try:
                    out.append({"addon": name, "event": event, "status": "ok",
                                "hook": bound.name,
                                "result": bound.method(**payload)})
                except Exception as exc:  # noqa: BLE001 — fail-open, always
                    print(f"[Atlas WARN] addon {name!r} hook {bound.name!r} "
                          f"failed on {event!r}: {exc!r}", file=sys.stderr)
                    out.append({"addon": name, "event": event,
                                "status": "failed", "hook": bound.name,
                                "error": repr(exc)})
    return out


def list_addons() -> list[dict]:
    """Every discovered addon with its manifest + enabled/compatible state.

    Backs `atlas addon list`. Does not import/register anything beyond what
    discover_plugin_modules() already does for its own has-a-register()
    check.
    """
    enabled_globally = _plugins_enabled()
    disabled = _disabled_names()
    out: list[dict] = []
    for mod_path in discover_plugin_modules():
        name = mod_path.rsplit(".", 1)[-1]
        manifest = read_manifest(name)
        out.append({
            "name": name,
            "enabled": enabled_globally and name not in disabled,
            "compatible": compatible(manifest),
            "version": (manifest or {}).get("version", ""),
            "description": (manifest or {}).get("description", ""),
            "author": (manifest or {}).get("author", ""),
            "min_atlas_version": (manifest or {}).get("min_atlas_version", ""),
            "has_manifest": manifest is not None,
        })
    return out


def register_plugins(mcp) -> list[str]:
    """Load and register all discovered plugins. Returns registered plugin names."""
    if not _plugins_enabled():
        return []
    disabled = _disabled_names()
    registered: list[str] = []
    for mod_path in discover_plugin_modules():
        name = mod_path.rsplit(".", 1)[-1]
        if name in disabled:
            continue
        try:
            mod = importlib.import_module(mod_path)
            result = mod.register(mcp)
            # Plugins may return False to mean "skipped / inactive" (e.g. an
            # addon whose external binary isn't provisioned) — do not list
            # those as registered.
            if result is False:
                continue
            registered.append(name)
        except Exception as exc:  # noqa: BLE001
            print(f"[Atlas WARN] plugin {mod_path} register() failed: {exc!r}",
                  file=sys.stderr)
    if registered:
        print(f"[Atlas] plugins registered: {', '.join(registered)}", file=sys.stderr)
    return registered


def install_from_zip(name: str, zip_bytes: bytes) -> dict:
    """Extract an uploaded addon zip to plugins/<name>/ — the upload half of
    what `atlas addon create` scaffolds by hand. See docs/addons.md: an
    addon is trusted Python code with no sandboxing, so this is deliberately
    strict rather than permissive:

    - `name` must be a valid Python package name (same rule as
      cmd_addon_create) and plugins/<name>/ must not already exist — no
      silent overwrite of an installed addon via re-upload.
    - Every zip member must extract inside plugins/<name>/ — an absolute
      path, a `..` segment, or a symlink pointing outside is refused
      (zip-slip). Symlinks themselves are refused outright rather than
      validated, since a relative symlink's target isn't knowable until
      the filesystem resolves it later.
    - The zip must contain a top-level __init__.py, or it's refused before
      extraction — an addon missing this is silently invisible to every
      other function in this module, which is worse than refusing upfront.

    Does not import or register the addon — discovery picks it up on the
    next `register_plugins()` call (next server start), same as any addon
    dropped in by hand."""
    name = (name or "").strip()
    if not _NAME_RE.fullmatch(name):
        raise PluginError(
            f"addon name {name!r} must be lowercase letters/digits/"
            f"underscore, starting with a letter (matches a Python package name)")
    dest = (_REPO_ROOT / _PLUGINS_PKG / name).resolve()
    if dest.exists():
        raise PluginError(f"plugins/{name}/ already exists")

    try:
        zf = zipfile.ZipFile(BytesIO(zip_bytes))
    except zipfile.BadZipFile as exc:
        raise PluginError(f"not a valid zip file: {exc}") from exc

    for info in zf.infolist():
        if info.is_dir():
            continue
        # S_IFLNK bit in the upper 16 bits of external_attr — reject any
        # symlink member outright rather than resolve+validate its target.
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            raise PluginError(f"refusing symlink member in zip: {info.filename}")
        target = (dest / info.filename).resolve()
        if dest != target and dest not in target.parents:
            raise PluginError(f"zip member escapes plugins/{name}/: {info.filename}")

    # docs/addons.md's checklist step 1 — __init__.py at the addon root is
    # what makes plugins.<name> importable at all. Without it the zip would
    # extract "successfully" into an addon discover_plugin_modules() can
    # never see: invisible in list_addons(), never registered, no error
    # anywhere — the worst kind of silent failure. Reject it upfront
    # instead. (Zip member names here are root-relative, e.g. "plugin.py"
    # — the zip holds an addon folder's *contents*, not the folder itself.)
    top_level = {info.filename for info in zf.infolist() if not info.is_dir()}
    if "__init__.py" not in top_level:
        raise PluginError(
            "zip has no top-level __init__.py — required for plugins."
            f"{name} to be importable (see docs/addons.md). Zip the "
            "*contents* of your addon folder, not the folder itself.")

    dest.mkdir(parents=True)
    try:
        zf.extractall(dest)
    except Exception:
        import shutil
        shutil.rmtree(dest, ignore_errors=True)
        raise

    manifest = read_manifest(name)
    return {
        "name": name,
        "has_register": (dest / "__init__.py").is_file() or (dest / "plugin.py").is_file(),
        "has_manifest": manifest is not None,
    }
