# Atlas Second Brain Router

You are operating inside Atlas's local-first second brain: the durable, cross-case
knowledge base for this DFIR project. Any capable LLM agent (Claude Code, the
`bin/atlas` CLI analyst, or another tool) uses this file as the canonical
instructions. Tool-specific files (e.g. `CLAUDE.md` sections) are thin adapters
that point back here — any drift between an adapter and this file is a defect.

Your job: use this repository as durable context, keep it clean, and update it
safely when durable information is learned.

## Prime Directive

Before answering questions about past cases, forensic tool behavior, techniques,
threat actors, accuracy history, or prior decisions, inspect the relevant
second-brain files first. Do not guess when a memory file, wiki page, run
summary, or index may contain the answer. If information is missing, stale,
ambiguous, or low-confidence, say so.

## Repository Map

All paths relative to `brain/`.

### Durable Memory
- `memory/MEMORY.md` — curated cross-case facts (the index of what Atlas knows)
- `memory/preferences.md` — analyst preferences (report style, tooling choices)
- `memory/current-focus.md` — what the project is working on right now
- `memory/open-loops.md` — unresolved questions and follow-ups (checkbox list)

### Wiki (structured knowledge)
- `wiki/cases/` — one page per investigated case: outcome, learnings, accuracy
- `wiki/tools/` — forensic tool gotchas and usage knowledge (Volatility, plaso, EZ tools, TSK, …)
- `wiki/techniques/` — TTPs, artifact interpretation, attack patterns
- `wiki/actors/` — threat-actor knowledge accumulated across cases
- `wiki/concepts/` — synthesis pages and cross-cutting concepts
- `wiki/environments/<client-slug>/` — client environment baselines
  (naming conventions, topology, AD structure, SIEM/EDR coverage,
  known-benign admin patterns). Injected only into runs that declare that
  client via `engagement.yaml` AND ship no ground truth. Baselines carry
  descriptive facts only — never verdicts or prior-incident IOCs (those
  belong in `wiki/cases/`), and are **never captured from agent runs**:
  they are authored by humans from client-provided material
  (`atlas brain new --type environment --client <slug>`).

### Logs (historical record)
- `logs/decisions/` — architecture and workflow decisions
- `logs/research/` — research findings
- `logs/runs/` — run summaries, one per meaningful agent run (auto-written by `atlas train`/`atlas run`)

### Inbox (staging)
- `inbox/raw/` — unprocessed captures
- `inbox/memory-candidates/` — proposed durable-memory updates awaiting review
- `inbox/processed/` — approved/consumed items

### Indexes
- `indexes/tag-index.md`, `topic-index.md`, `case-index.md`, `tool-index.md`,
  `source-index.md`, `graph-index.md` — rebuilt by `python brain/scripts/rebuild_indexes.py`
  (or `atlas brain reindex`). Use these to find relevant knowledge fast.

### Analytics
- `analytics/snapshots/` — JSON brain snapshots (growth history, cross-case accuracy)
- `analytics/reports/` — Markdown learning reports
- `analytics/globe/` — Brain Earth knowledge-graph data (`brain-globe.json`)

## Routing Rules

| Question is about… | Look in |
|---|---|
| A forensic tool's quirks/flags/failures | `wiki/tools/`, `indexes/tool-index.md` |
| An artifact, TTP, or attack technique | `wiki/techniques/`, `indexes/topic-index.md` |
| A past case (what happened, what we learned) | `wiki/cases/`, `logs/runs/`, `indexes/case-index.md` |
| A threat actor | `wiki/actors/` |
| A known client's estate (baseline, not findings) | `wiki/environments/<client>/` |
| Why something is done a certain way | `logs/decisions/` |
| Accuracy / learning progress | `analytics/snapshots/`, `analytics/reports/` |
| Current work and follow-ups | `memory/current-focus.md`, `memory/open-loops.md` |

## Retrieval Behavior

1. Identify the likely domain.
2. During a live investigation prefer `brain.consult` (contextual, deduped)
   over dumping large wiki excerpts into the system prompt.
3. Otherwise check the relevant indexes (or run `atlas brain search "<query>"`).
4. Read the most relevant source files.
5. Answer using stored information; cite file paths.
6. Mention uncertainty if information is missing or stale.
7. Offer to stage a memory candidate if the answer reveals a durable gap.

See `docs/architecture-brain.md` for the learning + retrieval design.

## Memory Write Modes

Default and only supported mode for agents: **staged**.

- Agents and automated hooks write ONLY to `inbox/memory-candidates/` and `logs/runs/`.
- Never write directly to `memory/`, `wiki/`, or `logs/decisions|research/` —
  those change only through human review (`atlas brain approve` /
  `atlas brain reject`) or explicit human instruction.
- Disposition every reviewed candidate with `approve` or `reject --reason` —
  never delete a candidate file: rejection archives it to `inbox/processed/`
  with the rationale, which keeps the audit trail and lets capture's
  content-hash dedup stop the same learning from being re-staged next run.
- When actually deciding accept vs reject, run an adversarial review — an
  independent reviewer argument and an independent challenger argument per
  candidate, challenger wins ties. In Claude Code this is the
  `brain/scripts/review_memory_candidates.py`; other agents follow the same two-sided
  process inline.
- Every candidate must include: date, source context (case/run), confidence,
  source classification, suggested destination, and why it is useful.

Capture (durable, reduces repeated explanation): tool gotchas, technique
insights, accuracy trends, decisions, reusable workflows, useful commands,
solved errors, open loops, research findings, security notes.

After each finished investigation, **background learning**
(`core/brain/learn.py`) analyses the claim graph, memory, findings, reports,
tasks, corrections, and reviewer output (when present), then stages a **small**
set of high-confidence reusable lessons for Dashboard Brain Review.

**Daily command:** `atlas run` (learning is automatic). Use `atlas train` for
lab cases that need an independent reviewer. See `docs/architecture-brain.md`.

Do NOT capture: secrets, credentials, tokens, private keys, session cookies,
raw evidence contents, victim/suspect PII, case IOC dumps, temporary facts,
large unprocessed output.

## Run Summaries

Each meaningful run creates `logs/runs/YYYY-MM-DD-HHMM-<case-id>-<command>.md`
covering: goal, verdict, findings by tier, accuracy metrics (when ground truth
exists), self-corrections, problems, open loops, candidates created, sensitive
items skipped.

## Analytics and Brain Earth

When asked "how much have we learned?", "show brain stats", "where is knowledge
stale?", or "show the brain earth / knowledge globe":

1. `atlas brain reindex`
2. `atlas brain stats` (writes a snapshot)
3. `atlas brain report --period <period>` for time comparison
4. `atlas brain globe` for the Brain Earth visualization, then open the printed
   dashboard URL (`/_dashboard/brain_globe.html`)

Always distinguish raw captures, processed durable knowledge, decisions,
resolved problems, open loops, and pending candidates. Analytics reward useful
learning, not note dumping.

## Security Rules

- Never store passwords, API keys, tokens, private keys, session cookies, or
  credential dumps anywhere under `brain/`.
- Case-derived text may contain real IOCs and credentials: it is redacted
  before staging; anything flagged `risk.contains_sensitive_data: true` or
  `source_classification: confidential` is excluded from indexes, analytics,
  the globe, and prompt injection (aggregate counts only) and cannot be
  approved until edited.
- If secret-like material appears in a file, stop and warn (path + pattern
  type, never the value).
- `AGENTS.local.md` holds local private context and is never committed.

### Internal / public split (private remote vs GitHub)

The brain has two audiences. **Raw captures are INTERNAL** — `brain/inbox/`,
`brain/logs/runs/`, `brain/analytics/deliverables/`, `brain/wiki/cases/`,
`brain/wiki/environments/`, `brain/memory/`, `brain/issue/` stay on a private
remote and are listed in `.gitignore-public`. Only **generalized
wiki** (`wiki/{concepts,techniques,tools,actors}`) and the regenerated
`indexes/` reach the public GitHub remote.

The promotion gate (`atlas brain approve`) is the ONLY bridge across the
boundary: it **hard-blocks** a candidate bound for the public wiki if it
contains case-specific identifiers/IOCs/PII (`core/brain/identifiers.py`) or
trips the case-specific heuristic — generalize it first (`atlas brain approve
--show-redacted` previews the redacted form). The publish path
(`atlas publish`), the `.githooks/pre-push` guard, and the CI leak-gate enforce
the same boundary. Never `git push origin` by hand; publish scrubbed snapshots
with `atlas publish --push`.

## Required End-of-Run Summary

At the end of every meaningful run, report: what was done, what was learned,
what memory was staged (never directly updated), what was skipped as sensitive
or low-value, which indexes/analytics were rebuilt, and open loops.
