# Investigation State (`.atlas/`)

Atlas stores **Current Investigation State** — the authoritative knowledge
representation of the case — primarily under `<case>/.atlas/`.

API: `misc.current_investigation_state` (full snapshot).
`claim.snapshot` returns the Claim Graph subset only.

This is separate from:

| Location | Role |
|----------|------|
| `evidence/` | Immutable inputs (read-only contract) |
| `analysis/` | Derived artifacts + **execution trace** (process audit) |
| `reports/` | Client deliverables (projections — not source of truth) |
| `CASE.md` | Investigator **work inbox** (Investigation Requests, plus an optional *What you already know* section for prior knowledge — Atlas seeds searches from its indicators, treats a theory as a lead and an environment fact as context, never as a finding or an allowlist) — not the state store. See [architecture-case-driven.md](architecture-case-driven.md). |

Lazy bootstrap: the first `atlas rerun` creates missing `.atlas/` files automatically. No manual migration.

---

## Ownership matrix (no fifth “open work” store)

| Concern | Owner | Not the owner |
|---------|--------|----------------|
| Human-editable open requests | `CASE.md` → Plane A reconcile | claim graph, memory |
| Actionable work queue + lifecycle status | `.atlas/investigation_tasks.json` | `investigation_memory`, `milestones.json` |
| Beliefs / findings | `claim_graph.json` + `finding_index.json` | CASE.md, tasks text |
| Invalidations / withdrawn beliefs | `invalidation_queue.json` + claim node status | task `dropped` |
| Continuity narrative (goals / questions prose) | `investigation_memory.json` | **not** a second task list — does not gate finish/report |
| Advisory chronology | `milestones.json` | never gates investigation |
| Disk access plan | `mount_plan.json` | CASE.md mount prose |

**Gate consumers:** finish status, `reason.pre_report_check` open-task / multi-request gates, and soft coverage disposition read **`investigation_tasks`** (and ledger/access SoTs). They must not treat `open_investigation_goals` / `outstanding_questions` as the work queue.

Do not add another JSON for “open questions” without retiring one of the rows above.

---

## Directory map

```text
<case>/
  .atlas/
    claim_graph.json              # Epistemic graph (observations → conclusions)
    evidence_catalog.json         # Evidence input fingerprints
    dependency_index.json         # evidence → claim-graph node fan-out
    invalidation_queue.json       # Current dirty set + stale nodes
    investigation_memory.json     # Lightweight investigation memory (not chat)
    investigation_tasks.json      # CASE.md work queue materialization (V1)
    investigation_plan.json       # Pre-execution orchestration checklist
    mount_plan.json               # Detected disk images + mount actions
    rerun_brief.md                # Continuity brief for the AI investigator
    milestones.json               # Advisory high-level milestones
    run_history/
      run-0001.json               # Investigation journal entries (what + why)
      run-0002.json
      …
    report_projection/
      manifest.json               # Section bindings, hashes, staleness
      sections/
        exec_summary.json         # AI-written section bodies (projection cache)
        initial_access.json
        …
```

---

## File reference

### `claim_graph.json`

Belief state: nodes (`observation`, `claim`, `hypothesis`, `conflict`, `conclusion`, `recommendation` — what the responder should do, resting on named claims) and edges (`derived_from`, `supports`, `tests`, `contradicts`, `supersedes`, `resolves`).

Statuses: `new` | `unchanged` | `updated` | `needs_review` | `conflict` | `superseded` | `withdrawn`.
A node returns from `needs_review` to `unchanged` through `claim.revalidate` (a cited re-read that still shows what it names; the review stays on the node as `review_history`) or leaves the current beliefs through `claim.supersede`. Every node marked over dirty evidence carries `invalidated_by` (the added, changed and removed paths that hit it; a derived node inherits its bases' paths); a node marked through a `derived_from` edge also carries `invalidated_via` (the bases it was marked for) and returns with them; a node marked in its own right needs its own re-validation.

Updated by `claim.*` tools and fail-open mirror from `misc.record_finding`.

### `evidence_catalog.json`

Fingerprints of files under `evidence/` (content hash, size, mtime, inode, `full` vs `sampled` mode). Used to detect added / changed / removed / touched units on `atlas rerun`.

Distinct from `analysis/evidence_index.db` (FTS over **tool output**).

### `dependency_index.json`

Mechanical reverse index: evidence paths / IDs → claim-graph node IDs. Powers `needs_review` invalidation when inputs change.

### `invalidation_queue.json`

Working dirty set after the latest Plane A scan:

- `dirty_evidence` / `dirty_paths`
- `stale_nodes`
- `affected_report_sections` (filled via report projection)

**Note in file:** dirty set is the *starting point* of investigation, not a hard boundary.

### `investigation_tasks.json`

CASE.md work-queue materialization (V1). Exact normalized-text fingerprints only —
prefer a duplicate task over a bad merge. Optional `superseded_by` links an
explicit supersession (human/tool); reconcile never fuzzy-merges on edit.
Status `dropped` means the CASE.md line left the inbox (legacy files may still
say `withdrawn` and migrate on load).

### `investigation_memory.json`

Not conversation memory. Derived **continuity narrative** snapshot of:

- validated conclusions  
- disproven / superseded assumptions  
- unresolved hypotheses  
- missing-evidence notes  
- open investigation goals *(claim/conflict continuity hints — not CASE requests)*  
- outstanding questions *(capped narrative; not the task SoT)*  
- **`analyst_context[]`** — the analyst's facts (IPs, accounts, expected activity), one entry per bullet of CASE.md's *What you already know* (`origin: case_md`, `fingerprint` of the normalised text), reconciled on every Plane A: a bullet added is a new entry, one removed is withdrawn, one written again comes back under its id. Entries written before this reconcile existed (no `origin`) are left alone. Merge-preserved across refreshes. Status `active` or `withdrawn`. Evidence fingerprints are never modified by these entries.

Refreshed when the Rerun Brief is built (`analyst_context` is preserved the same way as `outstanding_questions`). **Work-queue truth stays in `investigation_tasks.json`.**

Manage via:

```bash
atlas rerun -q "IP 10.0.0.5 is a legitimate admin jump host" --no-agent
atlas rerun --withdraw-context ac-0001 --no-agent
atlas rerun --correct-context ac-0001 -q "updated wording" --no-agent
```

### `rerun_brief.md`

Human/AI-readable continuity brief for the next investigation step. Regenerated each persist `atlas rerun`. Includes evidence dirty set, claims requiring review, **new and withdrawn analyst context** (every standing statement is in the system prompt's PRIOR KNOWLEDGE block, with its id), claims matched by context, and the rule: context is not a blind allowlist.

### `run_history/run-NNNN.json`

**Investigation journal** for one continuity run:

| Field | Purpose |
|-------|---------|
| `evidence_diff` | What changed in evidence |
| `invalidation` | What was marked `needs_review` |
| `journal[]` | Why — `{reason, summary, details, related_ids, ts}` |
| `why_summary` | Short human lines |
| `milestones_recorded` | Milestone IDs added this run |

Inspect: `atlas rerun --list-runs`, `atlas rerun --diff run-0001..run-0002`.

### `milestones.json`

Advisory chronology (ransomware confirmed, lateral movement, …). Sits **beside**
`investigation_tasks.json` — does **not** replace it. Never gates the
investigation or mutates claim/task statuses.

### `report_projection/`

Format-agnostic report projection:

- **manifest.json** — stable section IDs (client spine), contributing claims/conclusions/conflicts/evidence, hashes, timestamps, `missing`/`stale`/`current`, MITRE tactic tags
- **sections/\<id\>.json** — AI-generated prose bodies (cache of the projection, still not “truth”)
- **finding_index.json** / **case_config.json** (sibling under `.atlas/`) — stable `F-NNN` ids and report language

Assemble during a rerun writes temporarily to `reports/` root (`estate_report.md` / `host_<HOST>_report.md` preferred), then **promotes** into an immutable snapshot when investigation state changed.

### Immutable report history (`reports/`)

After the **first persist `atlas rerun`**, flat pre-rerun deliverables are migrated and later packs are snapshotted:

```text
reports/
  initial_report/     # original investigation reports (never overwritten)
  rerun_0001/         # complete pack after journal run-0001 (if material)
  rerun_0002/
  diff_report.md      # cumulative investigation-state change history
  latest -> rerun_0002/   # symlink to highest rerun_* or initial_report
```

- **SoT unchanged:** `.atlas/` Claim Graph / journal remain authoritative; folders are historical projections.
- **`diff_report.md`:** append-only, structured from fingerprints (claims, confidence, conflicts, analyst context, evidence) — **not** Markdown wording diffs.
- **No material change:** journal + a short `diff_report.md` note; **no** new `rerun_NNNN/`.
- **`atlas report`:** prefers `reports/latest`.

Assemble helper: `atlas rerun --assemble-report` (still valid; promote runs at end of persist `atlas rerun`).

---

## Relationship to the execution trace

| Concern | Store |
|---------|--------|
| What tools ran, gate results, lineage | `analysis/<CASE>_trace.json` |
| What we believe, conflicts, supersessions | `.atlas/claim_graph.json` |
| Why beliefs changed across evidence arrivals | `.atlas/run_history/` |
| What the client PDF/Markdown says | `reports/*` (projection) |

Dashboard Chain/Graph views read the **trace**. A Claim View over the claim graph is served by the dashboard (`dashboard/claim_view.html`).

---

## Operator tips

```bash
# After new evidence lands
atlas rerun --case ~/cases/mycase --no-agent

# Analyst context (interpretation only) — persist + mark matching claims
atlas rerun --case ~/cases/mycase -q "IP 10.0.0.5 is a legitimate admin IP" --no-agent

# Analyst context + AI reinvestigation from Rerun Brief
atlas rerun --case ~/cases/mycase -q "IP 10.0.0.5 is a legitimate admin IP"

# Read continuity
atlas rerun --list-runs
less ~/cases/mycase/.atlas/rerun_brief.md

# Deliverable from current projection (no LLM)
atlas rerun --assemble-report

# AI-refresh stale sections then assemble
atlas rerun --regenerate-sections
```

Do not hand-edit `reports/*.md` expecting Atlas to treat that as investigation state. Change beliefs in Current Investigation State (claims/conclusions), then regenerate the projection (`misc.write_projected_final_report` or `atlas rerun --regenerate-sections`).

---

## See also

- [architecture-investigation.md](architecture-investigation.md)  
- [cli-reference.md](cli-reference.md#atlas-rerun)  
