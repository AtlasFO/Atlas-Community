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
| [`report`](#atlas-report) | Render the case's main report (terminal, md, html, pdf), or export the ATT&CK Navigator layer or the STIX indicator bundle |
| [`write-report`](#atlas-write-report) | Write the report a stopped run still owes |
| [`status`](#atlas-status) | One-screen investigation health |
| [`explain`](#atlas-explain) | Explain a claim, conflict, or report section |
| [`timeline`](#atlas-timeline) | Case timeline from claims/journal (or master TSV) |
| [`journal`](#atlas-journal) | List / show / diff investigation journal runs |
| [`rerun`](#atlas-rerun) | Incremental investigation (Plane A + projection) |
| [`verify-trace`](#atlas-verify-trace) | Verify hash-chained trace mirror |
| [`brain`](#atlas-brain) | Durable cross-case second brain |
| [`publish`](#atlas-publish) | Scrubbed public snapshot |
| [`models`](#atlas-models) | List the models a provider serves |
| [`doctor`](#atlas-doctor) | Show resolved backends/models |
| [`serve`](#atlas-serve) | MCP server on stdio |
| `provider` | LLM providers: `setup` wizard, `list`, `test NAME [--model ID]`, `use NAME [--role ROLE] [--model ID] [--dry-run] [--no-probe]`, `profile init ID` (copy a shipped provider profile into your folder to edit), `profile path` ([llm.md](llm.md#provider-profiles)) |
| `share` | SMB evidence share: `enable`, `disable`, `status`, `passwd` (set or change the share's Samba password) |
| `addon` | Addons: `list`, `create NAME` |
| `intel` | Indicators and threat reports for a case: `add --file FILE` or `add --doc DOC` (`--format`, `--name`, `--tlp`, `--map`), `pull --source NAME`, `list [--all] [--json]`, `withdraw --id ID` or `--source NAME`, both with `--reason`, `sources` ([intel.md](intel.md)) |
| `autofill` | Propose CASE.md Evidence Links rows from the evidence (`--yes` accepts every suggestion) |
| `skin` | Pick the live-dashboard animation (`atlas`, `matrix`, `radar`, `wave`, `aquarium`); `--preview` prints a few frames |

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
atlas run [--case DIR] [-q "…"] [options]
```

| Option | Description |
|--------|-------------|
| `--case` | Case directory (default: the cwd when it looks like a case) |
| `-q`, `--question` | Optional override of the CASE.md Investigation Requests for this run; with neither, the standard objective |
| `-L`, `--language en\|de` | Report language, persisted in `.atlas/case_config.json` |
| `--remote HOST` | Run forensic tools on remote SIFT VM |
| `--remote-mode resident\|copy` | Evidence already on the VM (`resident`, the default), or copied up from here with the outputs synced back after the run (`copy`) |
| `--remote-workspace DIR` | Workspace on the VM for `--remote-mode copy` (default `~/atlas-workspace`) |
| `--output-dir DIR` | Mirror outputs outside the case (evidence stays read-only) |
| `--model` | Override the analyst provider's model |
| `--case-id ID` | Override the case id used for the trace file name of a fresh run |
| `--fresh` | Start fresh (see the start rule below) |
| `--resume` | Continue appending to the existing trace and phase stack; refused together with `--fresh` |
| `--all-tools` | Load tool namespaces up front until the schema budget is full (it follows the model's context window; `ATLAS_AGENT_MAX_OPENAI_TOOLS` or the provider profile's `max_tools` can change it); the rest still load on demand |
| `--interactive` | The agent may consult you at decision points (same as `atlas interactive`) |
| `--quiet` | No per-turn narration |
| `--json` | Machine-readable result on stdout (implies `--quiet`) |
| `--skin NAME` | Live panel animation for this run (`atlas`, `matrix`, `radar`, `wave`, `aquarium`); outranks `ATLAS_LIVE_SKIN` and the default saved with `atlas skin NAME` |
| `--no-brain` | No second-brain notes in the prompt and no learning after the run |
| `--capture-brain` / `--no-capture-brain` | Also stage the older review and self-correction candidates after the run, or never, whatever `ATLAS_CAPTURE_BRAIN` says; the background learning runs either way unless `--no-brain` |
| `--skip-sudo-check` | Skip the passwordless-sudo check at start (tests and CI only; a privileged tool still fails at run time). Also `ATLAS_SKIP_SUDO_CHECK=1` |

**Ending a run.** A run ends through one of the loop's endings (the model
finishes, or the loop writes the reports itself once the report gate passes),
or it stops before that. Every content class inside the evidence must end read,
partly read or left with a checked reason. The finish is held back once for
each set of undecided classes. A run that reaches any of its endings with a
class still undecided ends unfinished: `finish_status` is `stopped_undecided`
and the exit code is 2 (the dashboard's activity panel calls it
`undecided_evidence`). The report then carries an *Evidence not decided*
section naming each class, and `--resume` continues on those classes. For
`run`, `train` and `interactive`, a stop from the dashboard or a `kill -TERM`
writes the report the findings support, prints one line (`Run stopped on
request`) and exits with code 2, without a traceback. A stopped `atlas rerun`
(the dashboard's *Continue*) records `stop_requested` too, but ends with the
interrupt. Ctrl+C still raises its interrupt. A start without `--resume` after such an end clears the
working files (start rule below). The `--json` result and
`.atlas/run_status.json` name the ending; see [How a run ends](#how-a-run-ends).

**Start rule.** Without `--resume`, the previous run's working files are
cleared before the run starts when `--fresh` is given, when
`.atlas/run_status.json` records that a prior run ended (finished, stopped
or failed), or when `analysis/` still holds a trace or transcript of an
earlier process (a run that died without recording an end). The clear
moves the contents of `reports/`, the snapshot index and the traces and
transcripts in `analysis/` to `.atlas/run_history/trace-<stamp>/`, deletes
`analysis/` and `exports/`, and resets the ledger statuses and the session
beacon; claims, tasks and the plan under `.atlas/` are kept. A case that
has never run has nothing to clear. A start that would clear is refused
while a handling stop stands; `--resume` is not refused, and clears nothing. With
`--output-dir` the clear applies to that directory, never to the case. A run with
`--output-dir` of a case under a handling stop is refused, with or without `--resume`.

`ATLAS_LOOP` chooses how the run works its owed reads: `conversation` (the
default) or `frontier` (a queue of short single-purpose model calls; see
[architecture-investigation.md](architecture-investigation.md#6-coverage-the-work-order-and-the-incident-map)).
A case's trace keeps the loop it was started in.

**Outputs:** `analysis/<CASE_ID>_trace.json` (and its hash-chained mirror `analysis/<CASE_ID>_trace.jsonl`), the case report (`reports/<CASE_ID>_investigation_report.md`, or `reports/estate_report.md` with one `reports/host_<HOST>_report.md` per host with findings when the loop closes the run out), `exports/`, and Current Investigation State under `.atlas/` (including `claim_graph.json`). `atlas write-report` and a killed run's exit path use the case-id name too. `atlas report` and the dashboard pick the best-ranked of these reports (`core.report_snapshots.report_rank`: main report before host sections and notes, working copy before a snapshot's, estate before single-scope, then newest).

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
It takes the same options as `run` (same start rule), except `--quiet`,
`--json` and `--interactive`.

```bash
atlas interactive --case DIR -q "…"
```

---

## `atlas train`

Moves the prior reports and trace to `.atlas/run_history/` and deletes `analysis/` and `exports/` (unless `--no-clear`), runs a full investigation, then an independent reviewer grades the run.

```bash
atlas train --case DIR -q "…" [--no-clear] [--review-model MODEL]
```

It takes `run`'s `--case`, `-q`, `--model`, `--case-id`, `--output-dir`,
`--remote`, `--remote-mode`, `--remote-workspace`, `--all-tools`, `--quiet`,
`--json`, `-L`, `--skin` and `--skip-sudo-check`, plus:

| Option | Description |
|--------|-------------|
| `--no-clear` | Keep the existing reports, trace, `analysis/` and `exports/` |
| `--review-model MODEL` | Reviewer model id (default: `ATLAS_REVIEW_MODEL`, then the reviewer provider's model, then `REASON_MODEL`) |
| `--no-brain` | No second brain at all: no notes in the prompt, no candidates staged after the review |
| `--no-brain-capture` | Keep the notes in the prompt, stage no candidates after the review |

| Exit | Meaning |
|------|---------|
| `0` | Completed; review not NEEDS WORK |
| `1` | Reviewer or LLM error |
| `2` | Run did not finish |
| `3` | Review verdict NEEDS WORK |
| `4` | Run ended and the review passed, but coverage or beliefs do not support calling it complete; also when the reviewer refused a trace that belongs to another case |

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

| Option | Description |
|--------|-------------|
| `--live` | Review an in-flight run from its trace on disk |
| `--case DIR` | Case directory (default: the case the trace belongs to) |
| `--trace PATH` | The trace JSON (default: the active session's trace) |
| `-q`, `--question` | The case question, for context; without it a graded review takes the run's recorded objective |
| `--review-model MODEL` | Reviewer model id, as for `atlas train` |
| `--json` | Machine-readable result on stdout |

---

## `atlas chat`

Interactive session — you drive; the agent uses the same MCP tools and gates.

```bash
atlas chat [--case DIR] [--model ID] [--all-tools] [--skin NAME]
```

`--model`, `--all-tools` and `--skin` work as on `atlas run`.

---

## `atlas report`

Render the case's main report, the one the dashboard's Report tab shows (see
*Outputs* under `atlas run`), or export machine-readable artifacts derived
from the run's trace.

```bash
atlas report [--case DIR] [--format term|md|html|pdf|navigator|stix] [--output PATH]
```

| `--format` | What it does |
|------------|--------------|
| `term` (default) | The report, pretty-printed in the terminal |
| `md`, `html`, `pdf` | The report as that file, next to the report or at `--output` |
| `navigator` | An ATT&CK Navigator layer, `<CASE_ID>.navigator.json`, from the findings' validated technique ids (none, no file) |
| `stix` | The indicator list as a STIX 2.1 bundle, `<CASE_ID>.iocs.stix.json`, and the same rows as CSV, `<CASE_ID>.iocs.csv`. Only indicators a tool output that read evidence shows are exported, each with the first time the evidence shows it; values only named (in a finding, the brief or the threat context) are listed as context in the report's indicator file and never exported. |

`navigator` and `stix` write to the case's `exports/` unless `--output` names a
directory. The same files come from the `export.export_iocs` and
`export.export_navigator` tools during a run.

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
| `--from-master` | Read the Timeline Builder's `master_timeline.tsv`: from `reports/`, else the newest rerun snapshot, else `analysis/` (older cases wrote it there); error if none |
| `--limit N` | Max events to read and print (default 200; `0` = every row) |

---

## `atlas journal`

Ergonomic alias for journal inspection (`atlas rerun --list-runs` / `--diff`).

```bash
atlas journal                 # same as: atlas journal list
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
| `--assemble-report` | Stitch deliverable from `.atlas/report_projection/` (no LLM) into `reports/<CASE_ID>_report.<ext>` (`--format json`: `<CASE_ID>_report_projection.json`) |
| `--format` | `markdown` (default, alias `md`) / `html` / `pdf` / `json` when assembling |
| `--regenerate-sections` | Regenerate **stale** projection sections, then assemble |
| `--language`, `-L` | Report language `en`\|`de` (persisted in `.atlas/case_config.json`; reruns inherit when omitted) |
| `--model` | Override the analyst provider's model for Plane B |

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

- On the first rerun that writes (not `--dry-run`), the deliverable files at the top of `reports/` move to `reports/initial_report/`: every Markdown file except `diff_report.md`, HTML and JSON files with `report` in the name, timeline TSVs and trace JSON; PDFs, CSV files and sub-folders stay. `initial_report/` also receives `investigation_fingerprint.json` and `claim_snapshot.json` (no data loss)  
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
atlas verify-trace [--case DIR] [PATH]      # PATH: a trace.jsonl file or a case directory
```

---

## `atlas brain`

Durable cross-case second brain. Subcommands: `new`, `search`, `reindex`, `stats`, `report`, `review`, `approve`, `reject`, `sync`, `capture`, `learn`, `globe`.

```bash
atlas brain search "pass the hash"
atlas brain sync
atlas brain globe
```

| Subcommand | Options |
|------------|---------|
| `new` | `--type TYPE --title TITLE` (required), `--tags a,b`, `--client SLUG` (required for `--type environment`), `--force` |
| `search QUERY` | `--type TYPES`, `--limit N`, `--include-confidential` |
| `reindex` | `--verbose`, `--include-confidential` |
| `stats` | none |
| `report` | `--period week\|month`, `--since YYYY-MM-DD` |
| `review` | `--type TYPE` (candidate type), `--risk` (only candidates flagged sensitive) |
| `approve CANDIDATE` | `--yes` (no confirmation), `--show-redacted` (preview with case identifiers redacted, then exit) |
| `reject CANDIDATE` | `--reason TEXT` (required, kept as the audit record), `--yes` |
| `sync` | `--remote NAME` (default `origin`), `--branch NAME` (default `main`) |
| `capture` | `--case DIR` |
| `learn` | `--case DIR`, `--case-id ID`, `--question TEXT`, `--digest-only` (build the digest without a model call) |
| `globe` | `--case CASE_ID` (one case and its neighbourhood), `--topic TAG`, `--mode full\|growth\|quality\|security` |

Details: [second-brain.md](second-brain.md), `brain/AGENTS.md`.

---

## `atlas publish`

Build a scrubbed public snapshot and optionally push it.

```bash
atlas publish [--push] [--remote origin] [--branch public]
```

---

## `atlas models`

List the model ids a registered provider serves. A model list that comes in
pages is read to its last page.

```bash
atlas models [--provider NAME]
```

Without `--provider` the analyst's provider (`ATLAS_AGENT_PROVIDER`) is
asked; when no analyst provider is set the command stops and asks for
`--provider`. An implicit provider is never assumed. The command stops with
a message when the provider is unknown or has no API key.

---

## `atlas doctor`

Print the resolved configuration: the analyst's provider and model, the
reasoner and phase-director backends, each registered provider with its key
state, model and profile, and which provider the analyst, reviewer and
report roles use. The vision role appears in `atlas provider list`.

```bash
atlas doctor
atlas doctor --probe      # also GET /models on each provider a role uses or ATLAS_PROVIDERS declares (the only network call)
```

`--probe` contacts only the providers a role uses or `ATLAS_PROVIDERS`
declares; an implicit hub profile no role uses is not contacted.

Besides the roles it prints where the provider profiles are read from (the
shipped folder, and the ids your own `provider_profiles.local/` holds), every
profile that cannot be used with the file and the reason, and for each provider
the profile it binds to, by which rule (`preset`, `name` or `fallback`), the
file behind it and where its base URL comes from. A provider that sits on the
fallback profile at the host of a shipped profile gets a note naming the
`ATLAS_PROVIDER_<NAME>_PRESET` setting that would bind it. Details:
[llm.md](llm.md#provider-profiles).

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
| `1` | Generic failure (`run`: LLM or configuration error, or a crash; `train` / `review`: reviewer error) |
| `2` | Run did not finish (a requested stop of `run`, `train` or `interactive`, content classes left undecided, or a stop before any ending) / command error |
| `3` | Train review NEEDS WORK, or live review stalled |
| `4` | `run` / `train`: the run ended through one of the loop's endings, but coverage or beliefs do not support calling it complete |

`atlas rerun`: `0` success, `2` failure (e.g. bad `--diff`).

---

## How a run ends

`atlas run --json` and `.atlas/run_status.json` carry two fields.
`stopped_reason` says how the loop stopped. `finish_status` says whether the
investigation counts as done, and it decides the exit code.

These reasons are endings. Their `finish_status` comes from the coverage
verdict:

| `stopped_reason` | Meaning |
|------------------|---------|
| `finished` | The model called the finish and it was accepted |
| `closed_out` | The loop wrote the reports itself once the report gate passed |
| `report_stall` | The report gate was ready, the model never wrote the report, and the loop closed the phase |
| `finish_deferred` | The finish was held back for the report or for coverage, and nothing followed |
| `quiet` | No progress was detected |
| `stall` | The forensic tools stayed held behind the phase director's assessment |

| `finish_status` | Exit | Meaning |
|-----------------|------|---------|
| `complete` | `0` | Beliefs, the report, a synthesis, a ready pre-report check, no open question, no due read and every content class decided |
| `incomplete_coverage` | `4` | It ended, but coverage or an open question does not support calling it complete |
| `exited_degraded_incomplete` | `4` | It ended with no beliefs and no read still due |
| `stopped_undecided` | `2` | Content classes have neither a read nor a reason; the dashboard says `undecided_evidence`, and `--resume` continues |

These reasons are stops. Their `finish_status` is the reason itself, or
`interrupted` or `error` as noted:

| `stopped_reason` | Exit | Meaning |
|------------------|------|---------|
| `stop_requested` | `2` | The dashboard's Stop or a `kill -TERM` (`finish_status` `interrupted`); a stopped `atlas rerun` records it too but ends with the interrupt |
| `keyboard_interrupt` | interrupt | Ctrl+C (`finish_status` `interrupted`) |
| `llm_error` | `1` | The model provider failed (`finish_status` `error`) |
| `crashed` | `1` | An unexpected error (`finish_status` `error`) |
| `gate_deadlock` | `2` | Every recent tool call was refused |
| `model_refusal` | `2` | The provider's safety classifiers declined three requests in a row |
| `llm_deadline`, `llm_transport` | `2` | A model call ran past its deadline or stayed lost after the retries, where no wrap-up could follow |
| `turn_cap`, `wall_clock` | `2` | An internal lab limit on turns or elapsed time ended the run; neither is set by default |
| `loop_mode_refused` | `2` | A resume asked for the other `ATLAS_LOOP` mode than the trace was started in |

A run process that ended without recording any of these is shown in the
dashboard as `died`.

---

## Environment variables (high level)

| Variable | Role |
|----------|------|
| `LLMHUB_API_KEY` / `TSYSTEMS_API_KEY` | LLM Hub |
| `LLMHUB_BASE_URL`, `LLMHUB_MODEL` | Hub endpoint / default model |
| `REASON_BACKEND`, `DAIR_BACKEND` | The provider name the reasoner and the phase-director role use (`atlas provider use` and Settings write them) |
| `ATLAS_PROVIDER_<NAME>_PRESET` | The provider profile a registered provider binds to (setup writes it); a name that matches no profile makes the provider unusable |
| `ATLAS_PROVIDER_PROFILES_DIR` | Folder of your own provider profiles, instead of `provider_profiles.local/`; `~` is expanded, a relative folder is taken under the Atlas folder |
| `VISION_BACKEND`, `VISION_MODEL` | The optional vision role (a provider whose model takes images; the model id override) |
| `ATLAS_LOOP` | `conversation` (default) or `frontier`, how a run works its owed reads |
| `ATLAS_RAW_VIEWS` | `0` reads disk containers as they are instead of through read-only raw views |
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
