"""Atlas Addon SDK — see docs/addons.md for the full authoring guide.

    from core.addons import Addon, tool, hook

    class MyAddon(Addon):
        name = "my_addon"

        @tool()
        def hello(self, name: str) -> dict:
            return {"greeting": f"Hello {name}"}

This is a thin, friendlier layer over the FastMCP mount()/add_middleware()
calls every addon already had to make by hand — it is not a new runtime.
Addons still register through the same single stable integration point
(``core.plugins.register_plugins`` → ``server.py``); this package only
makes the *authoring* side easier.
"""
from .sdk import (AFTER_TOOL_CALL, EVENTS, REPORT_FINALIZED, Addon,
                  declares_event, hook, hooks_for, intel_reader, tool)

__all__ = ["Addon", "tool", "hook", "intel_reader", "EVENTS", "AFTER_TOOL_CALL",
           "REPORT_FINALIZED", "hooks_for", "declares_event"]
