# Atlas Second Brain

Local-first, Markdown-based durable knowledge for the Atlas DFIR project:
cross-case learnings, forensic tool gotchas, technique knowledge, accuracy
trends, and staged memory capture from agent runs.

Canonical instructions for any LLM agent: **[AGENTS.md](AGENTS.md)**.

## Quick start

```bash
bin/atlas brain new --type tool --title "Volatility symbol gotcha"
bin/atlas brain reindex
bin/atlas brain search "volatility"
bin/atlas brain stats
bin/atlas brain globe          # then open the printed dashboard URL
```

Standalone (no Atlas CLI, any agent):

```bash
python brain/scripts/new_note.py --type tool --title "..."
python brain/scripts/rebuild_indexes.py
python brain/scripts/search.py "query"
```

## Memory write mode

**Staged, always.** `atlas train` automatically writes a run summary to
`logs/runs/` and stages memory candidates in `inbox/memory-candidates/`.
Review with `atlas brain review`, promote with
`atlas brain approve <candidate> --yes`. Nothing writes `memory/` or `wiki/`
directly.

## Security

Never store secrets. Secret-like patterns are redacted before staging and
refused at indexing/approval. `source_classification: confidential` files are
excluded from indexes, analytics, the globe, and prompt injection.

Full documentation: [docs/second-brain.md](../docs/second-brain.md)
