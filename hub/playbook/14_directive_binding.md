## Directive Binding

After every `reason.*` call, extract `directives` from the response before proceeding.

- **`priority_tools`** — call these next, in order, before any other tools.
- **`skip_tools`** — do not call these for the current finding. Globs apply (e.g. `plaso.*` skips all plaso).
- **`focus_pids`** — pass as filter to all subsequent `vol.*` calls.
- **`focus_paths`** — pass as filter to all subsequent `tsk.*` / `ez.*` calls.
- **`curiosity_budget`** — after the work order is complete, the number of read-only exploratory probes you may run of your own choosing (see the execution loop, step 3). Each is logged via `misc.record_curiosity_probe`; 0 ⇒ none.
- **`next_hypothesis_triggers`** — after each tool result, if any trigger condition is met, call `reason.hypothesize` before continuing.

Directives are binding. `dair_assess` is the primary source of `priority_tools` — run nothing outside that list *except* the read-only curiosity probes its `curiosity_budget` authorizes (execution loop, step 3). After each `reason.*`, merge its directives into the active DAIR work order: append `priority_tools` not already listed; union `skip_tools`, `focus_pids`, `focus_paths`. DAIR directives take precedence on conflicts. Protocol blocks (`TOOL INFO` / deferred intents) are not failures — recover by `dair_assess` disposing deferred intents; never free-retry a blocked probe until it appears in `priority_tools`.

### Hypothesis conclusion extraction (mandatory)
When `reason.hypothesize` returns a conclusion that names specific search patterns, artifact types, file paths, or operations in body text — extract those as concrete tool calls and add them to the DAIR work order, **even if `directives.priority_tools` is empty**. Empty `priority_tools` from hypothesize ≠ "no follow-up needed". Parse for:
- Named patterns ("search for X in PCAP", "grep for Y", "look for Z cookie")
- Named artifact categories ("webmail cookies", "compose/send traffic", "recipient address")
- Named tools/operations ("run ngrep", "filter port 80", "follow TCP stream")

Convert each to a concrete MCP call and queue. Never skip in-text recommendations because the directive block is empty.

### Truncated output follow-up (mandatory)
When any tool result has `truncated: true` **or** `incomplete: true` /
`wall_clock_timed_out: true`, treat as **INCOMPLETE**. Before advancing phase
or recording a negative finding:
1. Diagnose why it stopped (file too large for the budget, pattern too broad,
   full-file stream on a multi-hundred-MB EVTX, etc.)
2. Re-run with a **narrower** strategy that can finish:
   - Prefer a time window (`time_start` / `time_end` on `ez.evtxecmd`, UTC) with a narrow `event_ids` set
   - Or raise `wall_clock_budget_s` after narrowing Event IDs
   - Or convert EVTX → CSV (`ez.evtxecmd` / Hayabusa) then `table.table_query`
3. If the original pattern was broad (e.g. a bare `sid=`), split into targeted
   sub-queries (e.g. `Cookie: sid=`, `<provider>\.com.*Cookie`, a specific host)
4. Only record a negative finding after a targeted retry returns empty —
   never after a broad truncated/timed-out scan alone
5. `reason.pre_report_check` **blocks Report** while critical auth/session
   scans (4624/4625/chainsaw) remain truncated without a successful
   non-truncated retry on the same `.evtx`. Do not "note the timeout and move
   on." The master timeline does **not** clear this debt.
