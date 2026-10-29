# Investigation Architecture

Atlas’s **investigation continuity** architecture: Current Investigation State,
the Claim Graph, the Rerun Engine (Planes A/B), investigation-driven Report
Projection, and Dashboard Claim View.

Complements [architecture.md](architecture.md) (MCP boundary, gates, executor)
and [investigation-state.md](investigation-state.md) (on-disk `.atlas/` layout).

---

## Design principles

1. **The AI investigator remains primary.** Structure exists to make investigations explainable, reproducible, and incrementally updateable — not to replace reasoning with templates.
2. **Process audit ≠ belief state.** The execution trace records *what the agent did*. **Current Investigation State** records *what we believe* and why (Claim Graph is one part of that state).
3. **The report is never source of truth.** Markdown/HTML/JSON are disposable projections of Current Investigation State (**investigation-driven**, not “graph-driven”).
4. **No silent overwrites.** Contradictions become Conflict Findings; supersession is explicit.
5. **Dirty set = start, not boundary.** Incremental reruns identify where to begin; the AI may explore further.

```text
Evidence
  → Plane A (tasks + plan + catalog)
  → AI Investigation
  → Current Investigation State   (authoritative)
  → AI Report Writer
  → Deliverable (md/html/json)    (projection only — never SoT)
```

CASE.md is the investigator **work inbox** only. See
[architecture-case-driven.md](architecture-case-driven.md).

---

## Big picture

```text
                    ┌─────────────────────────────┐
                    │     AI Investigator (LLM)    │
                    │  explore · hypothesize ·     │
                    │  challenge · conclude · write │
                    └──────────────┬──────────────┘
                                   │ promotes via claim.* / record_finding
           ┌───────────────────────┼───────────────────────┐
           ↓                       ↓                       ↓
   Execution Trace          Current Investigation     Investigation
   (process audit)          State (authoritative)     Journal / Memory
   analysis/*_trace.json    .atlas/ (claim graph ⊂ …)  .atlas/…
           │                       │
           │                       ↓
           │              Report Projection
           │              .atlas/report_projection/
           │                       │
           │                       ↓
           └──────────→   Assembled deliverable
                          reports/*.md
```

**API:** `misc.current_investigation_state` returns the full snapshot.
`claim.snapshot` returns the Claim Graph subset only.

**Optional:** Timeline Builder plugin may emit `analysis/master_timeline.tsv` as an *additional evidence source*. The pipeline must never depend on it.

---

## 1. Claim Graph

### Epistemic ladder

```text
Evidence Artifact
  → Observation      (single-source, low interpretation)
  → Claim            (investigator assertion)
  → Hypothesis       (competing explanations)
  → Conflict         (disagreement; main-report visible)
  → Conclusion       (after gates / reconciliation)
```

### Lifecycle states

| Status | Meaning |
|--------|---------|
| `new` | Newly created |
| `unchanged` | Current belief, not modified this run |
| `updated` | Current belief, modified |
| `needs_review` | Mechanically stale (e.g. upstream evidence changed) |
| `conflict` | Open conflict node |
| `superseded` | Replaced after reconciliation (history kept) |
| `withdrawn` | Retracted without replacement |

Legacy `active` / `resolved` migrate on load.

### Confidence

Unchanged: `CONFIRMED` · `LIKELY` · `SUSPECTED` · `UNCONFIRMED`

### MCP tools (`claim.*`)

| Tool | Role |
|------|------|
| `claim.add_observation` | Record observation |
| `claim.add_claim` | Record claim (+ validation) |
| `claim.add_hypothesis` | Competing hypothesis |
| `claim.add_conflict` | Conflict Finding |
| `claim.promote_conclusion` | Claim → conclusion |
| `claim.supersede` / `claim.resolve_conflict` | Explicit belief change |
| `claim.revalidate` | A belief under review re-checked against the current evidence and unchanged: cites the re-reading calls (held to the citation test), returns it to `unchanged`, keeps the review as history, and brings back what went under review only through it |
| `claim.detect_contradictions` | Hard polarity scan (e.g. auth success vs none) |
| `claim.snapshot` | Snapshot for report grounding |

`misc.record_finding` remains the gated finding path and **fail-open mirrors** into the claim graph.

### Contradiction policy

- Never silent replace; never auto-merge.
- Open conflicts appear in the **main report body**.
- Supersede only after recorded reconciliation.

### Negative / temporal / host-vs-estate rules

- Prefer: *“No evidence of compromise was identified within the available evidence.”*  
  Forbidden: *“This host was not compromised.”*
- `first` / `earliest` claims require an explicit `temporal_qualifier`.
- Host reports: host findings + host recommendations only (soft-link to Estate Report).

---

## 2. Rerun Engine

### Two planes

| Plane | Role (shipped today) |
|-------|------|
| **A — Deterministic** | Fingerprints, dependency fan-out, optional analyst-context match → `needs_review`, journal, brief, projection staleness |
| **B — AI / continuity** | **With `-q`:** AI reinvestigation from Rerun Brief + analyst context, then stale section regen. **Without `-q`:** regenerate stale report sections (`--regenerate-sections` / bare `atlas rerun`); never treats Markdown as SoT |

Bare `atlas rerun` (no `-q`, without `--no-agent`) regenerates stale projection sections and assembles the report. With `-q` and without `--no-agent`, Plane B starts a Hub AI session seeded by `.atlas/rerun_brief.md` and the analyst context (evidence is never mutated by context). Always-on agent for every dirty set (no `-q`) remains deferred.

CLI entry: [`atlas rerun`](cli-reference.md#atlas-rerun).

### Plane A pipeline (`--no-agent`)

1. Lazy bootstrap of `.atlas/` (no manual migration)
2. Scan `evidence/` → fingerprints → catalog diff  
3. Optional: persist analyst context (`-q` / withdraw / correct) — interpretation only  
4. Rebuild dependency index → mark dependent claims `needs_review`; union with context-matched nodes  
5. Write Rerun Brief + refresh investigation memory (preserves `analyst_context[]`)  
6. Append investigation journal run + advisory milestones  
7. Rebind report projection sections → mark stale (no LLM)

### Rerun Brief

Written to `.atlas/rerun_brief.md`. Includes:

- New / modified / removed evidence  
- Claims requiring review  
- Open conflicts  
- Unresolved hypotheses  
- Previously superseded conclusions  
- New / withdrawn **analyst context** + interpretation rule (not a blind allowlist); every standing statement is in the system prompt's PRIOR KNOWLEDGE block  
- Claims potentially affected by analyst context  
- Outstanding questions  
- Explicit note: dirty set is a **starting point**

### Investigation journal

Each persist rerun appends `.atlas/run_history/run-NNNN.json` with:

- Evidence diff + invalidation snapshot  
- `journal[]` entries: `{reason, summary, details, related_ids, ts}` — **what and why**  
- `why_summary` for humans months later  

Example reasons: `evidence_added`, `evidence_modified`, `claim_needs_review`, `contradiction_detected`, `milestone_recorded`, `analyst_context_added`, `analyst_context_withdrawn`, `analyst_context_corrected`, …

### Milestones

`.atlas/milestones.json` — high-level chronology (first confirmed compromise, lateral movement, ransomware, persistence confirmed/disproved, …).

**Advisory only.** Never gates investigation or mutates claim statuses.

---

## 3. Report Projection (investigation-driven)

### Principle

```text
Current Investigation State → Relevant Context → LLM → Section → Markdown Assembly
```

Do **not** treat “edit the Markdown file” as the update model.
Do **not** call this “graph-driven” — the Claim Graph is necessary but not sufficient.

### Write path

| Path | When |
|------|------|
| `misc.write_projected_final_report` | Prefer when Current Investigation State `has_beliefs` (LLM + deterministic fallback) |
| `misc.write_final_report(path, content)` | Always supported (analyst prose / empty graph / legacy) |

Both share `pre_report_check` and client-facing lint. Grounding against Current Investigation State is advisory (one revision cycle). Per-host / estate filenames select projection scope. Cases without `.atlas/` behave as before.

### Stable section IDs (client spine)

`exec_summary` · `scope_evidence` · `key_findings` · `detailed_findings` · `timeline` · `gaps` · `recommendations` · `appendix`

`recommendations` is a projection of `recommendation` nodes — what the run recorded with `claim.record_recommendation`, the ATT&CK mitigations derived from substantiated findings, and the precautions seeded from *What you already know* — ordered open → urgency → basis tier, each line naming its basis. The same nodes feed the dashboard's Response view.

**What the sections say about coverage.** The report states what the run did
not do as plainly as what it found:

- *Answers to the Investigation Questions* are written per question by one
  model call over the findings that speak to it. Every sentence ends with the
  finding ids it rests on, and every host, account, file, address, time and
  number in it is checked against those findings (one repair round). An answer
  that does not pass prints the earlier text with a marked line under it. A
  question the analyst never closed carries "open" in its heading, and a part
  closes only by the analyst's own update, on the structure of the beliefs
  named for it, never on stored links or on words. A run of eight or more words
  copied from a cited belief's evidence is put in quotation marks.
- *Evidence Gaps and Open Questions* lists, among the open questions: each
  image that was only listed and not read, the high-value artifacts nobody read
  (each with the reason the run recorded, the read that failed, or a note that
  no reason was recorded), the indicators not searched in every relevant
  source, the planned reads not done, findings a gate refused that were never
  recorded again, extracted output not wholly read, and the picture classes no
  model could identify and why (descriptions off in the brief, no vision model,
  a model that takes no image).
- *Evidence not analysed*, under the gaps, comes from the coverage ledger
  (section 6): every item or content class that was left (with its kind, reason
  and the calls that prove it), partly read, parsed with no row looked at, or
  still pending. *Evidence not decided* lists the classes a stopped run left
  with neither a read nor a reason, for a person to decide, and *Depth of
  analysis per host* gives each host's decided classes per cost tier.
- *Limitations* carries the lines code states whatever a model wrote: a stop
  with the reads still due, the report gate's issues at the run's end, the
  incident window's residual risk, and every recurring value the run ruled out
  only in a disposition (with the value, its kind and the disposition's own
  clause), so a value kept out of the findings is still said.
- The Executive Summary is written in the frame the brief states (engagement,
  system owner, the brief's question) and in none when the brief states none;
  its next steps are rendered from the recorded response plan ("no step
  recorded" when there is none). The Attack Timeline never shows a tool's own
  run time as an event.

MITRE tactics remain **tags** on findings (`finding_tactics`), not separate H2 sections. Legacy ids (`initial_access`, …, `conflicts`) alias to `detailed_findings` / `appendix` for `atlas explain --section`.

Stable finding ids: `F-NNN` in `.atlas/finding_index.json`. Report language: `.atlas/case_config.json` (`en`|`de`), set when a case is created in the dashboard or via `--language` / `-L`.

### Manifest fields (per section)

- Contributing claims / conclusions / conflicts / evidence  
- Binding fingerprint  
- Content hash, `generated_at`, `generator_version`  
- Status: `missing` | `stale` | `current`  
- Explicit `depends_on` (e.g. Initial Access → Exec Summary, Timeline, Recommendations)

### Generation

- `--no-agent` / Plane A: rebind + mark stale only  
- Bare `atlas rerun` / `--regenerate-sections`: rewrite stale sections from investigation state (LLM or deterministic fallback)  
- `--assemble-report [--format markdown|html|json]`: stitch deliverable from section store  

Storage: `.atlas/report_projection/` (mutable cache). Deliverables under `reports/`
become an **immutable history** after the first persist rerun:

- `initial_report/` — migrated pre-rerun reports
- `rerun_NNNN/` — complete pack aligned with journal `run-NNNN` when state changed
- `diff_report.md` — cumulative investigation-state change log
- `latest` → symlink to the newest snapshot

LaTeX output remains deferred; PDF renders from the report's Markdown through fpdf2 (`core/report_pdf.py`).

---

## 4. Dashboard Claim View

Projects beliefs from the claim graph. The Process view stays the audit of the execution trace — do not merge claim edges into it.

| View | Source | Role |
|------|--------|------|
| **Claim View** | `.atlas/claim_graph.json` | Claims, hypotheses, conflicts, conclusions, supersessions |
| **Process view** | `analysis/*_trace.json` | Tool / reason / DAIR lineage |

- UI: `dashboard/claim_view.html?case=<dir>` (optional `&node=C0004`)
- API: `GET /_dashboard/api/claim_graph?case=` · `GET /_dashboard/api/investigation_state?case=`
- Trace viewer: **Claims ↗**
- CLI companions: `atlas status`, `atlas explain`, `atlas timeline`

Non-goals: editing the graph in-browser; replacing the Process view.

---

## 5. Compatibility with existing Atlas

| Existing | Relationship |
|----------|----------------|
| Execution trace | Still required; process audit |
| Finding gates | Unchanged; findings mirror into claims |
| `write_final_report` | Fully compatible; prefer `write_projected_final_report` when beliefs exist |
| `current_investigation_state` | Full authoritative snapshot |
| Timeline Builder | Optional plugin only |
| Process view | Audit of the trace (unchanged) |
| Claim View | Belief projection (additive) |

---

## 6. Coverage, the work order and the incident map

Three stores answer "what has the run done, and what does it still owe?".
They sit beside the claim graph; none of them holds a belief.

### Coverage ledger (`.atlas/coverage_ledger.json`)

Every evidence item handed over (a disk image, a memory image, a collected
tree, a file, an archive, a capture) is a unit, and so is each content class
inside it (the event logs, the hives, the mail store ...). Each unit has a
disposition:

| State | Meaning |
|-------|---------|
| open (pending, relevant) | Not read yet. A pending unit is never counted as touched. |
| read | A successful content read named every file the class was built from. |
| partial | Some of its files were read; the count is kept and moves with the reads. |
| parsed | A parser wrote output nobody has looked at; it stays open with a next step. |
| left | Not read, for a stated kind (unlikely to help, by an observation from a read on the same host; outside the incident window; outside the scope; a duplicate of other evidence; unreadable; unrelated content; and two kinds only code sets, empty and no reader), a reason and the calls that prove it. |

One reader decides what a call read, and the ledger, the extracted outputs,
the contents index, the evidence items and the work order all credit through
it. A listing of an image is recorded apart from a read of its content; a read
through a mounted filesystem, an extraction from an image or a read by image
handle credits the image; a call over a folder does not credit every copy
below it. An extracted class (a file class the tools wrote) that no call read
can be left only by a fact the code recomputes from the trace and the file
system (every reader the tool declares for it is installed and failed on two
distinct files, or every file is empty), never by the model's own verb. The
dashboard's Coverage tab and the report's *Evidence not analysed* read this
ledger.

Every content class ends read, partly read or left; "no reason recorded" is
not a state a finished run can carry. A class with neither is open work the
model sees every turn, per host and cheapest and highest-yield first. The
finish and the director's move to the report defer once for each set of open
classes. Leaving a class as unlikely to help takes an observation from a read
on the same host, one call per class label across hosts with an outcome per
host: the reason names its source, every address, account, file, hash or path
it names must show in that read, and "not needed for the question" is refused.
The other kinds rest on their own checked fact (the data's end date, the scope,
the copy, the failed reads). A class that holds a current attacker value cannot
be left. A run that reaches any of its endings with a class or evidence item
still undecided ends unfinished: `finish_status` is `stopped_undecided`, exit
code 2, and the dashboard's activity panel calls it `undecided_evidence`. The
report lists them under *Evidence not decided*, and a resume continues on them.
`ATLAS_EVIDENCE_DISPOSITION` (on by default) switches this rule.

The depth per host counts, for each cost tier (cheap, medium, hard), the
classes decided out of those the host holds. A tier comes from the calls and
time a reading needs, never from a list of artefacts. The work block, the
director's note, the pre-report check, the report (*Depth of analysis per
host*) and the Coverage tab state it, and nothing gates on it, with one
exception: a host-wide question (several hosts in scope, no single artefact,
value or host of its own) stays partial until every host in its scope has its
cheap and medium classes decided.

### The work order

The reads a run owes are kept in the trace as work items: a file, a path
inside an image or a search of a table, and why it is owed. They are shown to
the analyst every turn, last, as ready calls (up to six). An item closes when a
call reads its target or fails to; a question answered or dropped makes its
planned reads moot. Items are filled by a plan per question once the inventory
is done, by the director, by the file behind the timeline rows a claim rests
on, and by absence claims the contents index contradicts; unread index
artefacts and partly read series reach the director as proposals. Code never
maps a question to an artefact: it validates names against what exists. An
entry that is a tool name alone, or a host alone, makes no item, since nothing
could close it.

The report push, the first `atlas_finish` and the stall ladder's force-report
wait for due items until they are read, or until the order is neglected (shown
for `ATLAS_AGENT_REPORT_STALL_TURNS` turns without a read); the report lists
every planned read not done. The director reviews the order rather than
planning batches: it reads each question with its items and claims, what each
claim rests on, and the due, failed and proposed reads, and answers with work
items, adopted proposals and dismissals that name the call that already read
the target. A run is `complete` when it has beliefs, the report, a synthesis,
a ready pre-report check, no actionable question, no due read and every
content class decided; the ledger's
unseen units and the unmet obligations are recorded beside the label
(`coverage_disclosure`). `ATLAS_WORK_ORDER=0` restores the earlier run.

### Incident map (`.atlas/incident_map.db`) and the frontier loop

The map holds what the beliefs are about as data: hosts, accounts, files and
endpoints, timed events that connect them, and attacker, benign or unknown
labels the model sets, each citing the belief or the calls that show it. Code
never labels. A label stands only while the belief behind it does; two current
labels of different bases for one target raise a conflict. The map notes
values seen on a host before the attacker's stated arrival there, proposes the
hosts an attacker value reaches (by name, hash, account or endpoint; a host
with no attacker event gets a due read) and keeps the incident window from
stated arrivals and inbound edges. It feeds the model and the report; it has no
tab of its own. `devtools/rebuild_incident_map.py` rebuilds the map of a
finished run.

`ATLAS_LOOP` chooses how a run works the order. The default, `conversation`, is
one long conversation. `ATLAS_LOOP=frontier` runs the order as a queue of short
items, each one a fresh model call with at most ten tools and a submit that code
records through the same finding gates; attacker values from the map are counted
once per batch over the case's tables and saved outputs, and the map's changes
become items. The run ends when nothing is due. The frontier loop needs the map
(`ATLAS_INCIDENT_MAP`), and a case's trace stays in the mode it was started in:
a resume in the other mode is refused, and a fresh start converts it.

---

## Related docs

- [investigation-state.md](investigation-state.md) — `.atlas/` file map  
- [cli-reference.md](cli-reference.md) — `atlas rerun` / explain / status / …  
- [agent-instruction-architecture.md](agent-instruction-architecture.md) — modular playbook  
