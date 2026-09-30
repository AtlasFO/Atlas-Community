#!/usr/bin/env python3
"""Per-case chat worker — the backend behind the dashboard's chat window.

The dashboard (dashboard/serve.py) is one long-lived process serving many
cases; `bin/atlas chat` assumes one case per process (it chdir's into the case,
runs an in-process MCP toolbox keyed on the working directory, and registers
answer keys in a process-global table). Rather than fight those single-case
assumptions inside the shared server — and risk a heavy forensic tool (vol3 on
a memory image, say) hanging or OOM-killing the whole dashboard — each case
gets its own worker subprocess that runs the real `atlas chat` code path with
`cwd=case_dir`.

Protocol: newline-delimited JSON on stdin/stdout. **stdout carries protocol
frames only** — the UI runs quiet and everything else is redirected to stderr,
so library chatter can never corrupt the stream the dashboard parses.

    dashboard → worker (stdin)   {"type": "user", "text": "...", "role": "viewer|analyst|admin",
                                  "user": "<dashboard username, for the usage ledger>"}
                                 {"type": "shutdown"}
    worker → dashboard (stdout)  {"type": "ready", "case": ..., "model": ...}
                                 {"type": "tool_call", "name": ..., "args_preview": ...}
                                 {"type": "assistant", "text": "..."}
                                 {"type": "turn_done"}
                                 {"type": "error", "message": "..."}

Run as:  python -m agent.chat_worker --case DIR [--model M]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def deny_for_role(role: str):
    """The tool names a chat turn from this role may not call: a viewer
    reads the case, every other role works on it."""
    from agent.toolbox import CHAT_VIEWER_DENY_RE
    return CHAT_VIEWER_DENY_RE if (role or "").strip().lower() == "viewer" else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="atlas-chat-worker")
    parser.add_argument("--case", required=True, help="case directory")
    parser.add_argument("--model", default="", help="override LLMHUB_MODEL")
    args = parser.parse_args(argv)

    # The real stdout is the protocol channel. Point sys.stdout at stderr for
    # the rest of the process so the banner, the "starting MCP server…" note,
    # keyring messages, and any stray print() land on stderr — never in the
    # JSONL frames the dashboard reads off fd 1.
    proto = sys.stdout
    sys.stdout = sys.stderr

    def emit(obj: dict) -> None:
        proto.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
        proto.flush()

    try:
        from agent.cli import _bootstrap_env, _make_agent
        from agent.prompts import build_system_prompt

        _bootstrap_env()
        case_dir = Path(args.case).expanduser().resolve()
        if not case_dir.is_dir():
            emit({"type": "error", "message": f"case dir not found: {case_dir}"})
            return 1
        # Additive hardening over `bin/atlas chat`: block the case's grading
        # file(s) by realpath so a chat can't read a training case's ground
        # truth. Only ever blocks answer-key files — real engagements have none.
        try:
            from core import paths as _paths
            _paths.register_answer_keys(case_dir)
        except Exception:  # noqa: BLE001 — hardening is best-effort
            pass
        ns = argparse.Namespace(quiet=True, model=(args.model or ""),
                                all_tools=False, interactive=False)
        agent = _make_agent(ns, case_dir, command="chat")
        # The chat's tool calls go into the case's trace, as a run's do (a
        # second writer of a live run's trace is safe). The host-wide session
        # beacon names a run, never a chat: start_execution_log reads this.
        os.environ["ATLAS_SESSION_BEACON"] = "0"
        from agent.cli import _open_trace_before_plane_a
        _open_trace_before_plane_a(case_dir, save_session=False)
        # _make_agent forces interactive=True for command="chat"; the worker has
        # no console, so atlas_ask_analyst must fall back to "proceed
        # autonomously" (agent.loop._ask_analyst) instead of blocking.
        agent.interactive = False
        system = build_system_prompt(case_dir, interactive=False, chat=True)
        agent.messages = [{"role": "system", "content": system}]
    except SystemExit as e:
        # _make_agent sys.exit()s on a missing LLM Hub API key, etc.
        emit({"type": "error", "message": f"worker init failed: {e}"})
        return 1
    except Exception as e:  # noqa: BLE001
        emit({"type": "error",
              "message": f"worker init failed: {e.__class__.__name__}: {e}"})
        return 1

    emit({"type": "ready", "case": str(case_dir), "model": agent.client.model})

    from agent.llm import LLMError

    # readline() (not `for line in sys.stdin`) so a line is delivered as soon as
    # the dashboard writes it — the iterator form read-ahead-buffers and would
    # stall an interactive pipe.
    while True:
        line = sys.stdin.readline()
        if not line:  # EOF: the dashboard closed our stdin
            break
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        mtype = msg.get("type")
        if mtype == "shutdown":
            break
        if mtype != "user":
            continue
        text = str(msg.get("text") or "").strip()
        if not text:
            emit({"type": "turn_done"})
            continue
        agent.toolbox.deny = deny_for_role(str(msg.get("role") or ""))
        # The worker is shared by everyone who chats about the case; the
        # turn's spend is the sender's.
        from core import usage_ledger
        usage_ledger.configure(started_by=str(msg.get("user") or ""))
        try:
            agent.run_chat_turn(text, on_event=emit)
        except LLMError as e:
            agent._repair_pending_tool_calls()
            emit({"type": "error", "message": str(e)})
        except Exception as e:  # noqa: BLE001 — a bad turn must not kill the worker
            agent._repair_pending_tool_calls()
            emit({"type": "error",
                  "message": f"{e.__class__.__name__}: {e}"})
        emit({"type": "turn_done"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
