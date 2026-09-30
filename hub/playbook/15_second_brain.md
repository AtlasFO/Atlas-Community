## Second Brain (durable cross-case knowledge)

The repo carries a local-first second brain at `brain/` — the canonical
instructions live in `brain/AGENTS.md` (this section is a thin adapter;
treat any drift between the two as a defect).

Architecture + **recommended workflow**: `docs/architecture-brain.md`.

### Daily use

- **Normal investigation:** `atlas run` — reports first; Brain learning runs
  in the background automatically when the run finishes.
- **Lab / graded training:** `atlas train` — same investigation, plus an
  independent reviewer. Still grows the Brain.
- After a run, check **Dashboard → Brain Review** when candidates appear.
  Approve only high-quality reusable lessons.

### During the investigation

- Atlas auto-consults the Brain once per forensic topic (EVTX, MFT,
  Volatility, Scheduled Tasks, …) when matching tools succeed.
- You may also call `brain.consult` explicitly for a focused query.
- Never write `brain/memory/` or `brain/wiki/` directly — promote only via
  approve / Brain Review.

### Knowledge kinds

- **Lessons Learned** — do better next time (methodology, tool gotchas)
- **Knowledge Gained** — reusable forensic facts (behaviours, correlations)

Prefer few excellent candidates over many mediocre ones.
Never store secrets, IOCs, or customer-specific facts in the Brain.
