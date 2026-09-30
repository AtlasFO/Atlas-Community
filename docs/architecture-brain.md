# Atlas Brain — Lessons Learned architecture

This document explains how Atlas’s second brain grows and how it assists
investigations. Executable truth lives in `core/brain/` and
`tools/brain_tools.py`. Safeguards in approve / secrets / answer-key /
identifiers remain mandatory.

---

## Recommended daily workflow

**Real investigations → `atlas run`.**

```text
atlas run --case ~/cases/mycase
        ↓
investigation + report (immediate)
        ↓
background Brain learning (non-blocking)
        ↓
Dashboard → Brain Review  (when candidates appear)
        ↓
Approve / Edit / Reject
```

Investigators do **not** need to choose a special “learn” command. A finished
`atlas run` queues background learning automatically.

| Command | Use when |
|---------|----------|
| **`atlas run`** | Normal investigations (default) |
| **`atlas train`** | Training / lab cases that need an independent run review + grade |
| `atlas brain learn --case DIR` | Re-run learning manually (debug / missed job) |
| `atlas run --capture-brain` | Also stage legacy review-bullet candidates (optional) |

### When learning runs automatically

| Trigger | Learning |
|---------|----------|
| `atlas run` finishes successfully | Background learn **yes** |
| `atlas train` finishes | Capture summary + background learn **yes** |
| Run stopped unfinished | Learning **no** |
| `ATLAS_NO_BRAIN` / `--no-brain` | Learning **no** |
| `ATLAS_NO_BRAIN_LEARN=1` | Learning **no** (injection may still run) |

`atlas train` is **not** required for long-term Brain growth. Prefer `atlas run`
for production work; use `atlas train` when you want the independent reviewer.

After learning, open **Dashboard → Brain Review** when pending candidates
appear. Prefer rejecting mediocre lessons — quality over quantity.

---

## Philosophy

The Brain is an experienced forensic analyst’s notebook — not a case archive.

| Kind | Meaning | Examples |
|------|---------|----------|
| **Lessons Learned** | What we should do better next time | workflow, tool gotchas, methodology |
| **Knowledge Gained** | Reusable forensic facts discovered in practice | malware behaviour patterns, persistence correlations, overlooked artifacts |

Case facts (IOCs, hostnames, customer details) stay in the claim graph /
reports / `wiki/cases/` — they are **not** Brain lessons.

Human approval is still the only path into durable `memory/` and `wiki/`.

---

## Learning pipeline

```
Run finishes → reports available
        ↓
Background investigation learn (non-blocking)
        ↓
Digest: claims, memory, findings, reports, tasks, corrections, review
        ↓
LLM extracts ≤3 high-confidence reusable lessons
        ↓
Quality gates (strict: confidence=high, triviality, residue, identifiers, novelty)
        ↓
inbox/memory-candidates/  →  Dashboard Brain Review  →  approve/edit/reject
        ↓
wiki/… or memory/…
```

Legacy `capture.py` mining (review bullets / self-corrections) still runs on
`atlas train` and optionally via `--capture-brain`. The primary growth path is
investigation learning.

---

## Retrieval pipeline

| Layer | Role |
|-------|------|
| Tier A — `MEMORY.md` / preferences | Always inject (small, curated) |
| Tier D — environment baselines | Inject when engagement + no GT |
| Catalogue — concept/tool titles | Short index in the prompt |
| **Auto-consult** | On first use of EVTX / MFT / Volatility / … tools, middleware appends matching wiki notes once per topic |
| `brain.consult` | Explicit on-demand search (agent or playbook) |

Auto-consult (`core/brain/auto_consult.py`) does **not** load the whole Brain.
It fires once per topic per run, only when notes exist, and is capped in size.
Disable with `ATLAS_NO_BRAIN_AUTO=1`.

---

## Ops

```bash
atlas run --case DIR               # investigate; learn in background
atlas train --case DIR -q '…'      # + independent reviewer (labs)
atlas brain learn --case DIR       # re-run learning synchronously
# Dashboard → Brain Review
```

Disable: `ATLAS_NO_BRAIN=1` (all) · `ATLAS_NO_BRAIN_LEARN=1` (learn only) ·
`ATLAS_NO_BRAIN_AUTO=1` (auto-consult only).
