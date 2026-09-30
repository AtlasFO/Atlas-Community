"""Mapper package — readers + deterministic forensic normalization."""

from plugins.timeline_builder.mapper.dispatch import process_tool_result, should_finalize

__all__ = ["process_tool_result", "should_finalize"]
