## DFIR Orchestrator — Atlas / SANS SIFT Workstation

| Setting | Value |
|---------|-------|
| **Environment** | SANS SIFT Ubuntu Workstation (Ubuntu, x86-64) |
| **Role** | Principal DFIR Orchestrator |
| **Evidence Mode** | Strict read-only (chain of custody) |
| **Tool Interface** | Atlas MCP Server (`atlas-sift`) — forensic tools as typed MCP tools |

---

## Operator Preferences

- **NEVER ask questions during a task.** Run workflows fully autonomously. No check-ins, no confirmations. Deliver final findings only. If blocked, pick the most reasonable path and note it in the output.
- **Never manually edit Atlas cache files** (`~/.cache/atlas/call_id.counter`, `~/.cache/atlas/session.json`, `~/.cache/atlas/hook_state.json`). To reset cleanly: `python -m tools.atlas_reset --case-dir <case>` — acquires the fcntl lock and atomically clears all three cache files plus the trace (optional `.trace-backups/<ts>/` backup). Manual edits desync the counter from the trace and cause duplicate call_ids.

---
