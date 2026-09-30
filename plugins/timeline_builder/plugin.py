"""Timeline Builder — addon registration.

The SDK's worked ``@hook()`` example (see docs/addons.md): one method,
called after every tool call with the plain (tool_name, args, result)
triple — no MCP protocol types. This used to be a hand-rolled
``fastmcp.server.middleware.Middleware`` subclass; migrated here as part of
unifying every addon onto ``core.addons.Addon``, behavior unchanged.
"""
from __future__ import annotations

import sys
import traceback

from core.addons import REPORT_FINALIZED, Addon, hook
from plugins.timeline_builder.mapper.dispatch import process_tool_result, should_finalize
from plugins.timeline_builder.finalize import maybe_finalize_from_tool


class TimelineBuilderAddon(Addon):
    name = "timeline_builder"

    @hook()
    def capture(self, tool_name: str, args: dict, result) -> None:
        """Parallel timeline collection — runs after each MCP tool, fail-open."""
        evidence_ref = ""
        try:
            from core.middleware import _extract_evidence_ref
            evidence_ref = _extract_evidence_ref(args)
        except Exception:
            pass
        try:
            n = process_tool_result(
                tool_name, args, result, evidence_ref=evidence_ref)
            if n:
                print(f"[timeline_builder] +{n} events from {tool_name}",
                      file=sys.stderr)
            if should_finalize(tool_name, result):
                maybe_finalize_from_tool(tool_name, args, result)
        except Exception as exc:  # noqa: BLE001 — never break investigations
            print(f"[timeline_builder WARN] {tool_name}: {exc!r}",
                  file=sys.stderr)
            traceback.print_exc(file=sys.stderr)


    @hook(REPORT_FINALIZED)
    def finalize(self, case_dir: str, report_path: str) -> dict:
        """Write the curated master_timeline.tsv for a report just written.

        Core dispatches this after any final report lands, whichever writer
        produced it. The addon is optional: when it is switched off nothing
        here runs and the report simply has no curated timeline — core's own
        Attack Timeline section is built from the claim graph regardless.
        """
        from plugins.timeline_builder.finalize import finalize_timeline
        # An empty case_dir means the caller did not know it; the finalizer
        # resolves the active case itself in that case.
        return finalize_timeline(case_dir=case_dir or None,
                                 report_path=report_path or None)


def register(mcp) -> None:
    """Entry point for core.plugins.register_plugins()."""
    TimelineBuilderAddon().register(mcp)
