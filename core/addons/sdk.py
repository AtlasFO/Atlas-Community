"""The two decorators + base class addon authors actually use.

Design goal: an addon author never touches FastMCP's ``mount()``/
``add_middleware()`` or the MCP protocol types directly. They write plain
methods, mark them ``@tool()`` (a new forensic tool call) or ``@hook()``
(runs after every tool call, e.g. to observe/collect data), and subclass
``Addon``. Everything else — building the sub-server, mounting it under a
namespace, building the middleware bridge — happens in ``Addon.register()``.

Fail-open is not optional here: a hook raising must never break the
investigation that triggered it. ``_HookBridge`` catches and logs; it does
not re-raise.
"""
from __future__ import annotations

import inspect
import sys
from dataclasses import dataclass
from typing import Any, Callable


def tool(name: str | None = None, description: str | None = None) -> Callable:
    """Mark a method as an MCP tool this addon exposes.

    Registered under ``<addon.name>.<method name>`` (or ``name`` if given)
    when the addon mounts. Write it like any other Python method — type
    hints on the parameters become the tool's schema, same as a plain
    FastMCP ``@mcp.tool()`` function.
    """
    def decorator(fn: Callable) -> Callable:
        fn._atlas_tool = {"name": name, "description": description}
        return fn
    return decorator


# ── events ───────────────────────────────────────────────────────────────
# The vocabulary an addon can hook. Core dispatches these; an addon never
# learns where in Atlas the call came from. Add an event here, dispatch it
# from the one place in core that owns that moment, and document it in
# docs/addons.md — that is the whole extension contract.
AFTER_TOOL_CALL = "after_tool_call"
REPORT_FINALIZED = "report_finalized"
EVENTS = frozenset({AFTER_TOOL_CALL, REPORT_FINALIZED})


def hook(event: str = AFTER_TOOL_CALL) -> Callable:
    """Mark a method as a hook for one of the events in ``EVENTS``.

    ``after_tool_call`` — ``method(tool_name: str, args: dict, result)``
    after every MCP tool call completes. Observation only: the return value
    is ignored and an exception is logged, not propagated.

    ``report_finalized`` — ``method(case_dir: str, report_path: str)`` once a
    final report has been written, whichever writer produced it. Return a
    dict describing what the addon produced (it reaches the caller and the
    run's record); raising is caught and reported as a failed hook.

    An unknown event name is refused at decoration time rather than silently
    never firing.
    """
    if event not in EVENTS:
        raise ValueError(
            f"unknown addon event {event!r} — one of {sorted(EVENTS)}")

    def decorator(fn: Callable) -> Callable:
        fn._atlas_hook = {"event": event}
        return fn
    return decorator


def intel_reader(name: str, suffixes: tuple[str, ...] = ()) -> Callable:
    """Mark a method as a reader of threat-context files in a format of
    your own: ``method(path: str) -> Iterable[dict]``, each dict a row with
    at least ``value`` (docs/intel.md lists the other fields). ``name`` is
    what ``atlas intel add --format`` and a command source's ``_FORMAT``
    use; ``suffixes`` let ``atlas intel add`` pick the reader by file name.
    Rows are typed, normalised and judged by core, never trusted as given.
    """
    if not str(name or "").strip():
        raise ValueError("an intel reader needs a name")

    def decorator(fn: Callable) -> Callable:
        fn._atlas_intel_reader = {"name": str(name).strip(),
                                  "suffixes": tuple(str(s).lower() for s in suffixes)}
        return fn
    return decorator


@dataclass(frozen=True)
class _Bound:
    name: str
    method: Callable


def _bound_marked(instance: Any, attr: str) -> list[_Bound]:
    out = []
    for cls_attr_name, cls_attr in inspect.getmembers(type(instance)):
        if hasattr(cls_attr, attr):
            out.append(_Bound(cls_attr_name, getattr(instance, cls_attr_name)))
    return out


class Addon:
    """Subclass this, set ``name``, add ``@tool``/``@hook`` methods.

    See docs/addons.md for the full guide and a worked ``@hook()`` example
    (``plugins/timeline_builder/``).
    """

    name: str = ""

    def register(self, mcp) -> None | bool:
        """Called once by core.plugins.register_plugins() — do not call
        directly and do not override; override nothing, just declare
        @tool/@hook methods and set `name`."""
        if not self.name:
            raise ValueError(f"{type(self).__name__}.name must be set")

        tool_methods = _bound_marked(self, "_atlas_tool")
        hook_methods = _bound_marked(self, "_atlas_hook")

        if tool_methods:
            from fastmcp import FastMCP
            sub = FastMCP(self.name)
            for bound in tool_methods:
                meta = bound.method._atlas_tool
                sub.tool(name=meta["name"], description=meta["description"])(
                    bound.method)
            mcp.mount(sub, namespace=self.name)

        # Only after_tool_call belongs on the tool-call path. A hook for
        # another event must not be handed the (tool_name, args, result)
        # triple after every call — core dispatches it at its own moment.
        tool_call_hooks = [b for b in hook_methods
                           if b.method._atlas_hook.get("event") == AFTER_TOOL_CALL]
        if tool_call_hooks:
            mcp.add_middleware(_build_hook_middleware(self.name, tool_call_hooks))

        return True


def _build_hook_middleware(addon_name: str, hooks: list[_Bound]):
    """A real fastmcp Middleware instance bridging an addon's @hook methods.

    Insulates addon authors from fastmcp's Middleware base class / MCP
    protocol types — their methods only ever see (tool_name, args, result).
    Imported lazily so importing core.addons doesn't require fastmcp (addons
    may want to unit-test decorated methods without a server).
    """
    from fastmcp.server.middleware import Middleware

    class _HookMiddleware(Middleware):
        async def on_call_tool(self, context, call_next):
            result = await call_next(context)
            tool_name = context.message.name
            args = dict(context.message.arguments or {})
            for bound in hooks:
                try:
                    bound.method(tool_name, args, result)
                except Exception as exc:  # noqa: BLE001 — fail-open, always
                    print(
                        f"[Atlas WARN] addon {addon_name!r} hook "
                        f"{bound.name!r} failed on {tool_name!r}: {exc!r}",
                        file=sys.stderr,
                    )
            return result

    return _HookMiddleware()


def hooks_for(instance: Any, event: str) -> list[_Bound]:
    """The addon's bound methods hooking `event`, in declaration order."""
    return [b for b in _bound_marked(instance, "_atlas_hook")
            if b.method._atlas_hook.get("event") == event]


def declares_event(addon_cls: type, event: str) -> bool:
    """Whether the class hooks `event` — asked before instantiating, so a
    listing can name an addon that would handle an event while disabled."""
    return any(
        getattr(attr, "_atlas_hook", {}).get("event") == event
        for _, attr in inspect.getmembers(addon_cls)
    )
