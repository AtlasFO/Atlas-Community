# Case-Driven Investigation Architecture

**Status: shipped** — `investigation_tasks.json`, `investigation_plan.json`,
`mount_plan.json`, Evidence Links, and the Investigation Board are implemented
and wired into Plane A / finish / pre-report gates (not a proposal).

Atlas is a **case-driven DFIR investigation platform**: the investigator decides
*what* to investigate next; Atlas remembers *everything* already learned and
continuously drives the investigation forward.

This document explains the architectural intent so future changes preserve the
separation between the investigator inbox and Atlas's durable state.

Complements [architecture-investigation.md](architecture-investigation.md)
(claim graph, Plane A/B, report projection) and
[investigation-state.md](investigation-state.md) (on-disk `.atlas/` layout —
includes the SoT ownership matrix).

---

## Why CASE.md changed

Previously CASE.md mixed:

- investigation objectives
- evidence inventory tables
- mount instructions
- output path documentation
- long discipline restatements

That made CASE.md feel like a mini investigation log — and investigators often
pasted findings back into it “so Atlas remembers.”

**CASE.md is now only the investigator work inbox.**

It should contain:

1. Case identity (`**Case ID:** …`)
2. A simple list under `## Investigation Requests`

Nothing else is required. Append new bullets whenever new work appears.
No “Round 2” blocks, no manual task statuses, no findings, no report paste.

### Header rows that set the frame

Besides the case id and the requests, the brief can state field rows that
change how the case is read (`**Engagement:** examination`, or a table row, or
a bare `engagement: x`; the first word of the value decides, and German labels
and words are read too). A row Atlas does not recognise is reported, never
guessed.

| Row | Values | What it changes |
|-----|--------|-----------------|
| Engagement | `incident-response` (the default), `examination` | Examination is a device or image looked at after the fact. The owner's duties remain: a step applies to systems still in service, and what a finding still has to recover or preserve stays until that is done. |
| System owner | `victim`, `suspect`, or the row left out | `victim` is the incident frame: remediation goes to the owner. `suspect` is the device of the person under investigation: no remediation is addressed to its owner, only investigative next steps and legal process. With no owner named (or an unrecognised one) Atlas reads the case in a neutral frame: no side is assumed, a value gets a side only where a finding's cited output shows it, no first-hour precaution or owner remediation is seeded, and the report and the analyst's prompt say "SYSTEM OWNER: NOT NAMED". |
| Vision descriptions | `on` | Lets `images.describe` send a case picture to the provider of the vision role ([llm.md](llm.md)). Off unless every such row says an on-word exactly; a missing row, any other text or two rows that disagree is off. |

---

## Why findings are intentionally NOT in CASE.md

Findings, claims, hypotheses, conflicts, and conclusions already live in:

| Artifact | Role |
|----------|------|
| `.atlas/claim_graph.json` | Beliefs (epistemic ladder) |
| `.atlas/investigation_memory.json` | Lightweight derived memory |
| `analysis/*_trace.json` | Process audit |
| `reports/*.md` | Disposable projection |

Putting findings in CASE.md would create a second, hand-maintained source of
truth that drifts from the Claim Graph. Atlas owns memory; the investigator
owns only the work queue.

---

## Investigation Tasks

Materialized under `.atlas/investigation_tasks.json` by Plane A.

**V1 fields:** `id`, `text`, `status`, `related_claim_ids`, `superseded_by`,
`created_at`, `updated_at`.

Statuses Atlas owns: `open`, `in_progress`, `partial`, `answered`,
`blocked_missing_evidence`, `reopened`, `dropped`.

(`dropped` replaces the former task status `withdrawn`, which collided with
claim-graph / analyst-context vocabulary. Legacy files migrate on load.)

### Deterministic matching (V1)

Reliability over intelligence:

- Exact normalized text match → same task
- Any wording change (including “Host A” → “Host A for persistence”) → **new task**;
  the old open line is **dropped** from the inbox (not silently merged)
- Prefer creating a new task over accidental merges
- No LLM / NLP / fuzzy merge in V1
- Explicit supersession only via `superseded_by` (tool/human) — never auto-inferred
  from similarity
- No silent 50-cap on the task store (unlike narrative `outstanding_questions`)

Derived revisit tasks use a `[derived]` text prefix so they are not dropped
when CASE.md lines change.

---

## Investigation Planning

After tasks are reconciled, Plane A builds `.atlas/investigation_plan.json`.

The planner **does not** perform forensic analysis. It answers:

- Which tasks are actionable vs blocked?
- What should run first (`reopened` / `needs_review`-linked first)?
- Which dirty evidence paths and claims to revisit?
- Simple host/evidence focus hints

The agent executes the plan; DAIR remains the in-loop assessor during analysis.

```text
CASE.md
  → Investigation Tasks
  → Investigation Planning   (Plane A, deterministic)
  → Execution                (AI investigator + tools)
  → Claims / Findings
  → Report Projection
```

---

## Rerun / continuous investigation

Every `atlas run` and `atlas rerun` starts with Plane A:

1. Evidence catalog diff
2. CASE.md → task reconcile (Investigation Requests) and analyst-context
   reconcile (the bullets of *What you already know*, by exact text: a
   bullet added is a new entry, one removed is withdrawn)
3. Claim invalidation (`needs_review`: findings citing changed or removed
   evidence, findings naming what a changed fact names)
4. Mount plan (+ safe E01 auto-mount when unambiguous)
5. Derived revisit tasks (simple, new ids only)
6. Investigation plan
7. Rerun brief, opening with *Why this rerun*
8. The work summary: evidence delta, findings to re-validate, open
   conflicts, open questions, facts added or withdrawn (`work` in the
   journal record, on the dashboard's Overview, and the one bit
   `atlas rerun` reads)

`atlas run` then starts the investigator from tasks + plan + prior claims
(a full pass: the previous run's working files are cleared first).
`atlas rerun` starts it from the Rerun Brief only when the work summary has
anything in it, with the open questions as its objective; otherwise it says
nothing changed and regenerates stale report sections only.

`--question` / `-q` on `atlas run` is an **optional override** for one
session. Default objectives come from open investigation tasks / CASE.md
requests. On `atlas rerun`, `-q` is a **fact for the brief**: appended to
*What you already know*, kept as analyst context, re-opening the findings
it names.

---

## Evidence and mounts

- Place evidence under `evidence/` (lowercase). Atlas discovers it automatically.
- Optional **`## Evidence Links`** in CASE.md — short host ↔ path ↔ kind map
  (table preferred). Parsed into `.atlas/evidence_links.json` and used as
  authoritative `focus_hosts` / `focus_evidence` seeds, orchestrator path
  boost, and Rerun Brief context. Supports `alias` (e.g. MDE name → image
  host) and `principal` rows. This is **not** a findings dump — keep it short.
- `.atlas/mount_plan.json` lists detected images (**shipped**).
- Auto-mount (V1): unambiguous E01/Ex01 under `case/mnt/<stem>/`.
- Disk containers (VMDK, VHD, VHDX, QCOW2, VDI) are read without a copy
  through a read-only raw view (below). ISO, encrypted and ambiguous images
  stay plan only.
- `<case>/mnt/` is a protected path segment (same write refusal class as
  `evidence/`).

### Naming / ordering answers

| Question | Answer |
|----------|--------|
| What is `<stem>`? | `Path(image).stem` of the **first** E01/Ex01 segment (e.g. `disk.E01` → `disk`). Later segments (`.E02`…) are not separate mount-plan images — libewf opens the set from `.E01`. |
| `_dashboard/` | **URL path prefix** on the dashboard HTTP server (`/_dashboard/...`), not a per-case directory beside the case root. |
| Auto-mount vs hash? | Plane A **catalogs `evidence/` first**, then for each E01 auto-mount runs **`hash.verify_evidence_hash`** (sampled OK) **before** `ewf.mount_full_image`. |
| Tasks vs `milestones.json`? | **Beside**, not a replacement. Tasks are the CASE.md work queue (gates); milestones stay advisory chronology only. |
| Plane A auto-mount privilege? | Privileged by design. Default `ATLAS_PLANE_A_AUTO_MOUNT=auto` mounts only when passwordless sudo is available; `off` = plan-only; `force` = attempt anyway. |
| Non-NTFS E01? | Soft `plan_only` (gate `non_ntfs`) — not a Plane A hard failure; agent uses tsk.*/plaso on the EWF device. |
| Remount after teardown? | `mount_full_image` reuses existing `ewf1` and `mount_ntfs` reuse logic; already-mounted `case/mnt/<stem>/fs` is not remounted. |

### Disk containers and raw views

The Sleuth Kit build Atlas runs reads raw images only, and a split or renamed
VMDK names its extents in its descriptor. Instead of converting each container
to a raw copy, Atlas serves the disk as one read-only regular file:
`qemu-storage-daemon` exports it over FUSE, without root, with a snapshot
chain applied, at `mnt/<image>/disk`. The contents index, the Sleuth Kit tools
and plaso read that file, so a case of many images needs no free space for
copies and a renamed VMDK opens. The view's state is kept in the image's entry
in `mount_plan.json`; a view daemon is infrastructure, never a read, so it
leaves no trace entry.

A container is untrusted input. Atlas pins the format from the file's name and
magic, never lets qemu guess, and checks that every file the container names
is a regular file under the image's own folder before qemu opens it. A
container that names a file outside its folder or a network location, or whose
parent qemu does not apply (a differencing VHD or VDI, a VMDK delta without
its parent or made on a changed parent), is refused with the reason, rather
than shown with zeros where the parent's data belongs. A snapshot base is an
earlier state of the disk and is read on demand.

A view needs `qemu-storage-daemon` with a FUSE export, `fusermount3` and a
usable `/dev/fuse` (`install.sh` installs `qemu-utils`; a container without
`/dev/fuse` falls back to the copy), and local tools: with `--remote` the
tools run elsewhere and no view is served. Without a view the copy,
`img_vmdk_export_raw`, stays; it keeps the case volume's free-space floor and
is refused while a view serves the disk. A tool run as root is refused on a
view. The run-end teardown stops the views except the ones a running
background job still reads. `ATLAS_RAW_VIEWS=0` switches views off: the
readers then take the container as it is.

### Files inside images

At intake Atlas lists every disk image of the case once (`fls -r -m /` per
filesystem volume) into the **contents index**, `.atlas/contents_index.db`,
and joins it with what the case's exports parsed. The index is a pointer and a
disclosure, never a floor: nothing in it asks for a read. What it gives:

- `tsk.index_find` finds a file inside any image of a host without running
  `fls`; a search with more matches than its limit returns one line per
  directory, and a read state filter (`unread`, `partial`, `read`, `skipped`)
  shows what no call has read.
- The analyst is shown one line per host (file count, commonest extensions,
  the largest directory trees few other hosts hold) after the inventory and
  again after compaction, and the per-question plan sees what each host's
  image holds where it will look.
- An **image handle**, `<image>::<path>`, is accepted by any parser. The image
  is named by its path, file name, stem or host label (`@<offset>` picks a
  volume), and the path is the one inside the image. Atlas extracts the file
  first, under `analysis/extracted/`; the result says which copy it read and
  which call extracted it, and the parse's trace entry names that extraction.
  `job_start_image_extract(images, paths, dest)` copies one path, glob or
  folder from several images (or all of them) as one background job, so a
  single parser call over the folder reads them all.
- An export is an index of what an image holds and the image is the authority:
  event logs, mail stores and captures the index lists inside the images count
  as present, never as absent, and an absence claim is checked against the host
  it names. A file named with its host joined by a hyphen
  (`corp-ws01-triage.raw`) maps to that host.

### Readers by input format

Which tool parses an event log, a hive, a Prefetch file or a mail store is not
left to the model's memory. Each tool declares the media types it reads in its
own registration, and the "readers by input format" table that the analyst's
guidance and the director's review carry is built from those declarations and
from the content type libmagic finds (`python-magic`), so carved pictures,
documents and archives name a reader too. A strings pass, text grep or text
read over an input whose format has an installed parser is refused with the
parsers named, for planned reads and the analyst's calls alike
(`ATLAS_FORMAT_READER_ROUTING`). A tool refuses an input that is not its kind,
and a folder handed to a one-file reader.

---

## Discovery-first filesystem access

**Authoritative discovery always overrides LLM assumptions.**

The agent may reason about evidence *content*. It must not invent
filenames, directory layouts, parser export names, mount paths, or
analysis paths when inventory / listing / catalog can answer.

| Piece | Role |
|-------|------|
| `core/discovery_first.py` | Path knowledge (`.atlas/path_knowledge.json`), unique-sibling / inventory resolve, repeat-guess quarantine |
| Middleware input-path gate | Auto-rewrite when discovery yields a unique match; else `gate: discovery_first` as **TOOL INFO** with `discovery_next` |
| Evidence Inventory / `list_evidence_dir` / catalog | Existing authoritative sources — reused, not duplicated |
| DAIR | Injects discovery tools after path-guess storms; strips failed guesses from `focus_paths`; does not advance phase treating invented paths as “absent media” |

Recovery: missing path → discovery (or one auto-resolve) → retry once with
the discovered path. The same invented path is never re-attempted as a
forensic tool call.

---

## Investigation Orchestrator (LLM + resource planning)

Atlas treats investigation as continuous resource allocation, not token
trimming alone (see `core/investigation_orchestrator.py`):

- Plane A builds `.atlas/investigation_plan.json` via the orchestrator:
  tasks, claims, findings, catalog, **tool capabilities**, and
  **context budget** → scored **candidates** (`score` = value × tool fit ×
  budget fit × cost).
- **Context Budget** (`core/context_budget.py`) is one input: remaining
  tool-output room + `detail_policy` (`full` / `filtered` / `summary` /
  **artifact_only**).
- **Disk-first, LLM-second:** large single-file bulk parses write CSV/JSON
  on disk; agent-facing output is `gate: artifact_ready` (+ profile).
  Multi-file directories soft-refuse with affinity-ranked shards (`TOOL INFO`).
- `core/coverage.py` plans **full coverage** only as last resort: chunk via
  `table.*` windows — not by re-dumping raw sources into the LLM.
- Middleware stays thin (refuse / compact / no-repeat); ranking lives in
  the plan, not a pile of gates.
- **Stewardship:** each agent turn re-runs `refresh_orchestration` (budget +
  plan). Claim/task saves set a dirty latch. LIVE shows `ctx` policy and
  next action.
- **Flat-score LLM rank:** when top candidate scores are nearly tied,
  optionally reorder *only within the existing list*
  (`ATLAS_ORCH_LLM_RANK=auto|off|force`; off unless set).

---

## Dashboard

Per-case **Investigation Board** (URL
`/_dashboard/investigation_board.html` — `_dashboard` is a route prefix, not
a folder under the case):

- Task statuses and counts
- Current investigation plan steps
- Live poll while an agent transcript is recently active

State is always scoped to the selected case directory.

---

## How investigators should work

1. Create a case from `case-template/`.
2. Write Case ID + Investigation Requests in CASE.md.
3. Drop evidence into `evidence/`.
4. Run `atlas run` (no `-q` required if CASE.md has requests).
5. Watch progress on the Investigation Board / Claim View.
6. When new questions or facts appear, **append** bullets to CASE.md
   (Investigation Requests, *What you already know*) or type them into the
   dashboard's start dialog, drop new evidence under `evidence/`, and
   continue with `atlas rerun` (the dashboard's *Continue*). `atlas run`
   starts over: same findings and questions, all evidence examined again.
7. Never paste findings into CASE.md — update happens in Atlas state.
