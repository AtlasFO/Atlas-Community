# Atlas CLI Reference

Complete reference for `bin/atlas` (and `atlas` when on `PATH`).  
Companion docs: [cli.md](cli.md) (tutorial-style), [llm.md](llm.md), [try-it-out.md](try-it-out.md).

```bash
atlas [--version] <command> [options]
```

Inside a case directory (`CASE.md`, `evidence/`, or `analysis/` present), `--case` is optional.

---

## Command index

| Command | Purpose |
|---------|---------|
| [`guide`](#atlas-guide) | In-terminal orientation |
| [`run`](#atlas-run) | Full autonomous investigation |
| [`interactive`](#atlas-interactive) | Supervised run (asks at decision points) |
| [`train`](#atlas-train) | Clean run + independent graded review |
| [`review`](#atlas-review) | Review a finished or live run |
| [`chat`](#atlas-chat) | Conversational analyst session |
| [`report`](#atlas-report) | Render the newest final report (terminal, md, html, pdf) |
| [`write-report`](#atlas-write-report) | Write the report a stopped run still owes |
| [`status`](#atlas-status) | One-screen investigation health |
| [`explain`](#atlas-explain) | Explain a claim, conflict, or report section |
| [`timeline`](#atlas-timeline) | Case timeline from claims/journal (or master TSV) |
| [`journal`](#atlas-journal) | List / show / diff investigation journal runs |
| [`rerun`](#atlas-rerun) | Incremental investigation (Plane A + projection) |
| [`verify-trace`](#atlas-verify-trace) | Verify hash-chained trace mirror |
| [`brain`](#atlas-brain) | Durable cross-case second brain |
| [`publish`](#atlas-publish) | Scrubbed public snapshot |
| [`models`](#atlas-models) | List LLM Hub models |
| [`doctor`](#atlas-doctor) | Show resolved backends/models |
| [`serve`](#atlas-serve) | MCP server on stdio |
| `provider` | LLM providers: `setup` wizard, `list`, `use NAME --role ROLE --model ID` |
| `share` | SMB evidence share: `enable`, `disable`, `status`, `set-password` |
| `addon` | Addons: `list`, `create NAME` |
| `autofill` | Propose CASE.md content from the evidence |
| `skin` | Pick the live-dashboard animation (`atlas`, `matrix`, `radar`, `wave`, `aquarium`) |

---

## `atlas guide`

In-terminal orientation for how Atlas works.

```bash
atlas guide
atlas guide setup
atlas guide brain
```

---

## `atlas run`

Full autonomous investigation: execution log → DAIR phase loop → gated findings → report.

```bash
atlas run --case DIR -q "CASE QUESTION" [options]
```

| Option | Description |
|--------|-------------|
| `--case`, `-c` | Case directory |
| `-q`, `--question` | Case question (required) |
| `--remote HOST` | Run forensic tools on remote SIFT VM |
| `--output-dir DIR` | Mirror outputs outside the case (evidence stays read-only) |
| `--model` | Override analyst model |
| Other | See `atlas run --help` |

**Outputs:** `analysis/<CASE>_trace.json`, `reports/`, `exports/`, and (when claim tools are used) Current Investigation State under `.atlas/` (including `claim_graph.json`).

---

## Report tools

Prefer `misc.write_projected_final_report` when Current Investigation State has
beliefs; `misc.write_final_report` remains fully compatible.

See [architecture-investigation.md](architecture-investigation.md).

| Tool | Role |
|------|------|
| `misc.current_investigation_state` | Full authoritative snapshot |
| `misc.write_projected_final_report` | Preferred when `has_beliefs` — projects state → Markdown through the same gates as `write_final_report` (LLM sections when available; deterministic fallback from state otherwise) |
| `misc.write_final_report` | Fully compatible analyst-written / legacy path (refused when beliefs exist) |

Section 7, Recommendations, is a projection of `recommendation` nodes recorded with `claim.record_recommendation` (plus ATT&CK mitigations derived from substantiated findings and precautions seeded from *What you already know*) — not prose written at report time. Whichever writer produced the report, the `report_finalized` addon event fires afterwards (the timeline addon writes its TSV there).
| `misc.write_case_document` | Custom analyst extract / briefing / notes under `analysis/` or `reports/` — **no** pre_report or projection gate; not the official final report |
| `claim.snapshot` | Claim Graph subset only |

---

## `atlas interactive`

Like `run`, but the agent may pause for operator guidance at decision points.

```bash
atlas interactive --case DIR -q "…"
```

---

## `atlas train`

Clears prior `analysis/` / `exports/` / `reports/` (unless `--no-clear`), runs a full investigation, then an independent reviewer grades the run.

```bash
atlas train --case DIR -q "…" [--no-clear] [--review-model MODEL]
```

| Exit | Meaning |
|------|---------|
| `0` | Completed; review not NEEDS WORK |
| `2` | Run did not finish |
| `3` | Review verdict NEEDS WORK |

Review: `reports/<CASE>_run_review.md`.

---

## `atlas review`

Independent review of a completed run, or **`--live`** for an in-flight (possibly stalled) investigation.

```bash
atlas review --case DIR
atlas review --live
atlas review --live --trace path/to/trace.json
```

Both read the trace from disk and never touch the running process. Without
`--live` the run is graded as it stands (`reports/<CASE>_run_review.md`, the
review `atlas train` writes; exit `3` = NEEDS WORK); the TTP coverage figure
comes from the trace's findings, as in a train review. Live review: exit `3`
= stalled. The review goes to the case the trace belongs to.

---

## `atlas chat`

Interactive session — you drive; the agent uses the same MCP tools and gates.

```bash
atlas chat [--case DIR]
```

---

## `atlas report`

Render the case’s newest final report in the terminal or as HTML.

```bash
atlas report [--case DIR] [--format html]
```

---

## `atlas status`

One-screen investigation health from Current Investigation State.

```bash
atlas status [--case DIR] [--json]
```

Shows: open conflicts, `needs_review` count, dirty evidence, stale/missing
projection sections, last journal run.

---

## `atlas explain`

Explain a belief or report projection section.

```bash
atlas explain C0004
atlas explain --section lateral_movement
atlas explain --conflict X0001
atlas explain C0004 --json
```

| Option | Description |
|--------|-------------|
| `node_id` | Claim / conclusion / hypothesis / conflict id (positional) |
| `--section ID` | Report projection section |
| `--conflict ID` | Conflict node (alias for positional id) |
| `--json` | Machine-readable output |

---

## `atlas timeline`

Case-level attack / investigation timeline (Timeline Builder optional).

```bash
atlas timeline [--case DIR] [--from-claims] [--from-master] [--limit N] [--json]
```

| Option | Description |
|--------|-------------|
| `--from-claims` | Default: claim graph timestamps + journal + milestones |
| `--from-master` | Parse `analysis/master_timeline.tsv` (error if missing) |
| `--limit N` | Max events to print (default 200) |

---

## `atlas journal`

Ergonomic alias for journal inspection (`atlas rerun --list-runs` / `--diff`).

```bash
atlas journal
atlas journal show run-0003
atlas journal diff run-0001..run-0003
atlas journal --json
```

---

## `atlas rerun`

**Continue the investigation from what changed.**

Two planes:

1. **Plane A (deterministic):** evidence catalog and fingerprints, dependency invalidation (`needs_review` on the findings that cite changed or removed evidence), CASE.md reconciled into tasks (Investigation Requests) and into analyst context (the bullets of *What you already know*), the Rerun Brief, the investigation journal, report-projection staleness. Always runs (unless `--list-runs` / `--diff` only). It ends with a **work summary**: evidence added, changed or removed; findings to re-validate; open conflicts; open questions; facts added to or withdrawn from the brief.
2. **Plane B:** when the work summary has anything in it and `--no-agent` is not set, the investigator starts from the Rerun Brief, told why the rerun runs and what to answer (the open questions, or else the delta itself). Its session ends the way a run's does: status recorded, exit report written when the analyst wrote none. When nothing changed, no investigator starts; stale report sections are regenerated and assembled (also via `--regenerate-sections`).

`-q` on `atlas rerun` is a **fact for the brief**: it is appended to the *What you already know* section of CASE.md, kept as analyst context, and the findings that mention what it names are marked for review. It is not the case-question override that `-q` is on `atlas run`. Editing the section by hand, or through the dashboard's Brief tab or start dialog, is the same channel: a bullet added is a new entry, a bullet removed is a withdrawn one, and only what changed re-opens findings.

The **dirty set is a starting point**, not a hard investigation boundary. Analyst context improves interpretation; it is **not** a blind allowlist.

```bash
atlas rerun --case DIR                              # continue from what changed
atlas rerun --case DIR --no-agent                   # record the changes only (no AI)
atlas rerun --case DIR -q "IP 10.0.0.5 is a legitimate admin jump host"
atlas rerun --case DIR -q "..." --no-agent          # add the fact, mark needs_review, no AI
atlas rerun --withdraw-context ac-0001 --no-agent   # the bullet leaves CASE.md too
atlas rerun --correct-context ac-0001 -q "updated context" --no-agent
atlas rerun -L de --assemble-report                 # German headings; evidence untranslated
atlas rerun --dry-run --json
atlas rerun --list-runs
atlas rerun --diff run-0001..run-0002
atlas rerun --assemble-report
atlas rerun --assemble-report --format html
atlas rerun --assemble-report --format json
atlas rerun --regenerate-sections
```

| Option | Description |
|--------|-------------|
| `--case`, `-c` | Case directory |
| `--question`, `-q` | A fact for the brief's *What you already know*: appended to CASE.md, kept as analyst context; findings that mention what it names are re-validated |
| `--withdraw-context AC_ID` | Withdraw a prior `analyst_context` entry (e.g. `ac-0001`); its bullet leaves CASE.md |
| `--correct-context AC_ID` | Withdraw `AC_ID` and replace with `-q` text (`supersedes` link recorded) |
| `--no-agent` | Plane A only (no AI session, no auto section regeneration) |
| `--dry-run` | Scan/diff without writing catalog/journal/projection/context updates |
| `--json` | Also print machine-readable JSON |
| `--full-hash` | Read and hash every evidence file in full: large images, and files unchanged since the last scan (which otherwise keep their recorded hash) |
| `--list-runs` | List investigation journal runs + milestones |
| `--diff RUN_A..RUN_B` | Compare two journal runs (what/why) |
| `--assemble-report` | Stitch deliverable from `.atlas/report_projection/` (no LLM) |
| `--format` | `markdown` (default) / `html` / `json` when assembling |
| `--regenerate-sections` | Regenerate **stale** projection sections, then assemble |
| `--language`, `-L` | Report language `en`\|`de` (persisted in `.atlas/case_config.json`) |
| `--model` | Override `LLMHUB_MODEL` for analyst-context Plane B |

**What `--no-agent` updates under `.atlas/`:**

- `evidence_catalog.json` — fingerprints  
- `dependency_index.json` — evidence → claims  
- `invalidation_queue.json` — dirty set + stale nodes  
- `claim_graph.json` — `needs_review` where dependents or analyst-context matches changed  
- `rerun_brief.md` — investigator continuity brief (opens with *Why this rerun*; analyst-context sections)  
- `investigation_memory.json` — lightweight investigation memory + `analyst_context[]` (one entry per bullet of *What you already know*)  
- `run_history/run-NNNN.json` — investigation journal (what + why + the `work` summary; reasons include `analyst_context_added` / `_withdrawn` / `_corrected`)  
- `milestones.json` — advisory milestones  
- `report_projection/` — rebind sections + mark stale  

**Immutable report snapshots (first persist `atlas rerun` onward):**

- Migrates existing flat `reports/*` → `reports/initial_report/` (no data loss)  
- After Plane B (or `--no-agent`), compares investigation fingerprints  
- On material change + new deliverables → `reports/rerun_NNNN/` (same NNNN as journal `run-NNNN`)  
- Appends to `reports/diff_report.md` (state-based, not Markdown diffs)  
- Updates `reports/latest` symlink  

See [investigation-state.md](investigation-state.md) and [architecture-investigation.md](architecture-investigation.md).

---

## `atlas write-report`

Write the report a stopped run still owes. Assembles it from the findings in
the claim graph — no network — and then upgrades it with the narrative
sections unless `--no-llm`. Needs nothing from the run's own process, so it
is the way back to a report after a run was killed outright.

```bash
atlas write-report [--case DIR] [--force] [--no-llm]
```

The result is written as `reports/<CASE-ID>_investigation_report.md` and
recorded as written on exit — never as the analyst's own deliverable. An
official report already in the case is left alone unless `--force`.

---

## `atlas verify-trace`

Verify the hash-chained trace mirror for a case.

```bash
atlas verify-trace [--case DIR]
```

---

## `atlas brain`

Durable cross-case second brain. Subcommands include `new`, `search`, `reindex`, `report`, `review`, `approve`, `reject`, `sync`, `capture`, `globe`.

```bash
atlas brain search "pass the hash"
atlas brain sync
atlas brain globe
```

Details: [second-brain.md](second-brain.md), `brain/AGENTS.md`.

---

## `atlas publish`

Build a scrubbed public snapshot and optionally push it.

```bash
atlas publish [--push] [--remote origin] [--branch public]
```

---

## `atlas models`

List model IDs available on the configured LLM Hub.

```bash
atlas models
```

---

## `atlas doctor`

Print which backend/model each role (analyst, reason, DAIR) resolved to.

```bash
atlas doctor
```

Run this before investigations if backends look wrong.

---

## `atlas serve`

Run the Atlas MCP server on stdio (for MCP clients such as Claude Code).

```bash
atlas serve
```

---

## Remote SIFT (`--remote`)

`run`, `train`, and `interactive` accept `--remote HOST`. Forensic tools execute on an external SIFT VM over SSH; agent/LLM traffic stays local. Host inventory: `~/cases/.common/live_hosts.json`. Full guide: [cli.md — Remote SIFT](cli.md#remote-sift-execution---remote).

---

## Exit codes (common)

| Code | Typical meaning |
|------|-----------------|
| `0` | Success |
| `1` | Generic failure |
| `2` | Run did not finish / command error |
| `3` | Train review NEEDS WORK, or live review stalled |

`atlas rerun`: `0` success, `2` failure (e.g. bad `--diff`).

---

## Environment variables (high level)

| Variable | Role |
|----------|------|
| `LLMHUB_API_KEY` / `TSYSTEMS_API_KEY` | LLM Hub |
| `LLMHUB_BASE_URL`, `LLMHUB_MODEL` | Hub endpoint / default model |
| `REASON_BACKEND`, `DAIR_BACKEND` | `llmhub` or other |
| `ATLAS_THEME` | CLI theme (`neon` / `atlas` / `mono`) |
| `ATLAS_FULL_HASH_MAX_GB` | Sampled vs full evidence fingerprints |
| `ATLAS_PLUGINS`, `ATLAS_PLUGINS_DISABLED` | Addons on/off (Settings → Plugins writes the second); off means off for tools and events alike |
| `ATLAS_AGENT_MODEL`, `REASON_MODEL`, `DAIR_MODEL`, `ATLAS_REVIEW_MODEL` | Per-role model overrides; outrank the provider's model, cleared when the role is assigned again under Settings → Providers |
| `ATLAS_RUN_NOTIFY_EMAIL` | Mail on run end for terminal runs |
| `ATLAS_SESSION_IDLE_HOURS`, `ATLAS_SESSION_MAX_HOURS` | Dashboard session limits (Settings → Sign-in and sessions writes these) |
| `ATLAS_SMTP_*` | Mail server (Settings → Mail writes these) |
| `ATLAS_MITRE_TABLE`, `ATLAS_MITRE_GROUPS`, `ATLAS_MITRE_SOFTWARE`, `ATLAS_MITRE_MITIGATIONS` | Where the ATT&CK tables are read from (default `~/cases/.common/`) |

Full lists: `atlas <cmd> --help`, [llm.md](llm.md).

---

## Related product docs

| Doc | Topic |
|-----|-------|
| [architecture-investigation.md](architecture-investigation.md) | Claim Graph, Rerun, Projection, Claim View |
| [investigation-state.md](investigation-state.md) | `.atlas/` layout |
| [dashboard.md](dashboard.md) | The dashboard: tabs, Settings, users, sessions, mail |
| [architecture.md](architecture.md) | MCP / security architecture |
