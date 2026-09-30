# Atlas Second Brain

A local-first, Markdown-based durable knowledge base at `brain/`: cross-case
learnings, forensic tool gotchas, technique knowledge, and accuracy trends —
consumable by the `bin/atlas` CLI analyst and by any other capable LLM agent
via the canonical router **`brain/AGENTS.md`**.

## Architecture

| Layer | Where | What |
|---|---|---|
| Router | `brain/AGENTS.md` | Canonical instructions for any agent |
| Memory | `brain/memory/` | Curated durable facts (`MEMORY.md`), preferences, current focus, open loops |
| Wiki | `brain/wiki/{cases,tools,techniques,actors,concepts,environments}/` | Structured DFIR knowledge, one YAML-frontmatter note per fact cluster; `environments/<client>/` holds client baselines (injected only for real engagements) |
| Logs | `brain/logs/{decisions,research,runs}/` | Historical record; run summaries auto-written by `atlas train` |
| Inbox | `brain/inbox/memory-candidates/` | Staged memory awaiting human review |
| Indexes | `brain/indexes/` | Regenerated lookup indexes (`atlas brain reindex`) |
| Analytics | `brain/analytics/` | JSON snapshots, Markdown reports, Brain Earth graph |
| Logic | `core/brain/` | All executable code; `brain/scripts/*.py` are standalone wrappers |

## Daily usage

**Start work** — ask the agent "what do we know about <tool/case/topic>?" or
run `bin/atlas brain search "volatility"`.

**During a run** — the `bin/atlas` analyst automatically receives a
`SECOND BRAIN CONTEXT` prompt section: `memory/MEMORY.md` + tool/technique
notes matched to the case's evidence types (disable with `ATLAS_NO_BRAIN=1`).
A case that declares a client via `engagement.yaml` (`client: acme-corp`)
and ships **no** ground truth additionally receives that client's environment
baselines from `wiki/environments/acme-corp/` — descriptive estate facts
(naming, topology, AD, logging coverage, known-benign admin patterns), never
verdicts or prior-incident IOCs, and never anything captured from an agent
run. Graded training cases never see this tier. Author baselines by hand:
`atlas brain new --type environment --client acme-corp --title "…"` and keep
`last_verified` current (reindex warns after 180 days).

**End of a train run** — `atlas train` stages memory automatically:

```text
brain: staged 4 memory candidate(s) (1 flagged sensitive); run summary: brain/logs/runs/...
```

Candidates come from the independent reviewer's recommendations, the run's
self-corrections, and (when the case ships `ground_truth.json`) an accuracy
data point. Capped at 8 per run, content-deduped across runs, and skipped for
STRONG verdicts except accuracy/self-corrections. `--no-brain-capture`
disables just this hook; `--no-brain` disables the whole brain for the run —
injection (via `ATLAS_NO_BRAIN`) *and* the capture hook. For non-train runs:
`atlas brain capture --case <dir>`.

**Review & promote** (the only path into durable memory):

```bash
bin/atlas brain review                 # list pending candidates
bin/atlas brain approve brain/inbox/memory-candidates/<file> --yes
bin/atlas brain reject brain/inbox/memory-candidates/<file> --reason "..." --yes
```

Rejection archives the candidate to `inbox/processed/` with the rationale —
never delete a candidate file, or capture's content-hash dedup will re-stage
the same learning on the next run. For the accept/reject decision itself,
`brain/scripts/review_memory_candidates.py` runs an adversarial panel
(independent reviewer + challenger per candidate; challenger wins ties).

**Weekly** — "how much have we learned?":

```bash
bin/atlas brain stats                  # terminal summary + JSON snapshot
bin/atlas brain report --period week   # Markdown report incl. accuracy trend
```

**Visualize** — Brain Earth, a dark clustered knowledge globe:

```bash
bin/atlas brain globe                  # writes brain/analytics/globe/brain-globe.json
bin/atlas-dashboard                    # then open:
# http://127.0.0.1:8765/_dashboard/brain_globe.html
```

Node color = type, size = connectivity + importance, brightness = recency,
red double border = open loop. Modes: `--case <id>`, `--topic <tag>`,
`--mode growth|quality|security`.

**Evolution replay** — once notes span more than one `created` date, a
timeline bar appears at the bottom of Brain Earth: scrub through dates or
press the play button to watch the brain grow day by day. Layout stays fixed, so notes
appear in their final position and the graph visibly fills in. Notes
without a valid `created` date are shown at every step.

## Security model

- **Staged-only writes**: agents and hooks write only `inbox/memory-candidates/`
  and `logs/runs/`; durable memory changes require `atlas brain approve`.
- **Secret detection**: secret-like patterns (keys, tokens, `password=`,
  bearer headers, `net use` passwords, …) are redacted to
  `[REDACTED:<type>]` before staging, refused at indexing, and hard-refused
  at approval. Warnings show the pattern type and path, never the value.
- **Confidential exclusion**: `source_classification: confidential` (set
  automatically when a candidate quotes evidence paths or >2 IOC tokens) is
  excluded from indexes, stats detail, the globe, and prompt injection —
  aggregate counts only. Such candidates can't be approved until edited.
- **Wipe safety**: `brain/` sits at the repo root, outside every path
  `clear_case_run` touches (pinned by `tests/agent/test_brain_hook.py`).
- `brain/AGENTS.local.md` is git-ignored for local private context.

## For non-Atlas agents

Everything works standalone with Python 3 + PyYAML:

```bash
python brain/scripts/new_note.py --type tool --title "..."
python brain/scripts/rebuild_indexes.py
python brain/scripts/search.py "query"
python brain/scripts/capture_run_memory.py --case <dir>
python brain/scripts/review_memory_candidates.py
python brain/scripts/approve_memory_candidate.py <candidate> --yes
python brain/scripts/brain_stats.py
python brain/scripts/brain_report.py --period week
python brain/scripts/brain_globe.py
```

## Future extensions (not implemented)

Semantic search (the note format is embedding-ready), graphml/gexf export
(the globe JSON already carries the full node/edge model), and autonomous
ingestion (staged capture stays the default stance: *stage first, review
before durable memory*).
