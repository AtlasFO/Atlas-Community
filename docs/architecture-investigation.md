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

## Related docs

- [investigation-state.md](investigation-state.md) — `.atlas/` file map  
- [cli-reference.md](cli-reference.md) — `atlas rerun` / explain / status / …  
- [agent-instruction-architecture.md](agent-instruction-architecture.md) — modular playbook  
