# Rerun Brief — RHINO-HUNT

Generated: 2026-09-29T16:46:20Z

## Investigation posture

The **dirty set is the starting point** of this investigation, not a
hard boundary. You MAY examine additional evidence, revisit assumptions,
form competing hypotheses, and challenge conclusions whenever needed.
You MUST NOT silently overwrite conclusions — use conflict / supersede.

## Why this rerun

- first look at 4 evidence files
- 4 open questions (4 new)

## Evidence Links (from CASE.md)

(none — add a `## Evidence Links` table in CASE.md to bind hosts/paths for the investigator)

## New Evidence

- `evidence/rhino2.log` (`ev_415b7f37d5342e0d`)
- `evidence/rhino3.log` (`ev_82d787513478995f`)
- `evidence/RHINOUSB.dd` (`ev_40c2309e1b04b84f`)
- `evidence/rhino.log` (`ev_ce77321b4f22c119`)

## Modified Evidence

(none)

## Removed Evidence

(none)

## Claims requiring review

(none)

## Existing open conflicts

(none)

## Existing unresolved hypotheses

(none)

## Previously superseded conclusions / claims

(none)

## New Analyst Context (this run)

(none)

## Analyst Context withdrawn (this run)

(none)

## Active Analyst Context (persistent)

(none)

## Analyst-context interpretation rule

Analyst context improves interpretation of known infrastructure,
accounts, and expected activity. It is **not** a blind allowlist:
legitimate jump hosts / admin accounts can still host malicious
activity (credential dumping, unusual auth, malware, out-of-scope use).
Distinguish *identity of infrastructure* from *nature of observed activity*.

## Claims / conclusions potentially affected by analyst context

(none)

## Outstanding investigation questions

(none)

## Evidence not yet examined

(none: every delivered item and high-value unit was read, blocked or handed over)

## Existing findings (0)

(none — this is the first pass over the evidence)

## Investigation Tasks

- **task-0001** [open]: Network traces — file transfers in all three pcaps (FTP, HTTP, an encrypted zip and its password, an executable).
- **task-0002** [open]: USB key — the key was reformatted: recover content by carving; two carrier images hold steganographic payloads (jphide) whose passwords are derivable from the recovered diary.
- **task-0003** [open]: Cross-evidence link — prove the connection between USB content and network traffic.
- **task-0004** [open]: The anti-forensics story — what the diary says happened to the hard drive and the USB key.

## Investigation Plan

Pre-execution orchestration (not forensic analysis). Follow these
steps as the starting checklist for this iteration.

### Context budget
- window≈1000000 tok · tool output room≈545478 tok · policy=rich
- Prefer single-file / filtered parses; after CSV exists use `table.*` — do not re-dump bulk parsers into chat.

### Investigation resources

- Open tasks: 4; revisit claims: 0; catalog units: 4
- Claims/findings ≈ 0 / 0
- Tool capability manifest: 2026-09-28.1
- Context budget is one resource. Rank actions by investigation value × tool fit × budget fit × inverse cost.

- **step-01** [inventory_evidence]: Call misc_inventory_evidence first — assess what exists, what is already parsed (consume those), what still needs processing, and what classes to skip. No mounts/parsers/DAIR/reason until then.
- **step-orchestrate** [follow_investigation_plan]: Orchestrator: policy=rich; tool room≈545478 tok. Prefer highest-score actions (value×tool×budget). Tabular spills → table.*; raw/disk exports → tsk.mmls (not table.*). Next: evidence/RHINOUSB.dd [tsk.mmls|summary|score=3.82], evidence/rhino2.log [strings.file_identify|summary|score=1.7], evidence/rhino3.log [strings.file_identify|summary|score=1.7], evidence/rhino.log [strings.file_identify|summary|score=1.7]
- **step-02** [examine_dirty_evidence]: Examine dirty evidence (4 path(s)) as the starting point (not a hard boundary).
- **step-03** [investigate_task]: [open] Network traces — file transfers in all three pcaps (FTP, HTTP, an encrypted zip and its password, an executable).
- **step-04** [investigate_task]: [open] USB key — the key was reformatted: recover content by carving; two carrier images hold steganographic payloads (jphide) whose passwords are derivable from the recovered diary.
- **step-05** [investigate_task]: [open] Cross-evidence link — prove the connection between USB content and network traffic.
- **step-06** [investigate_task]: [open] The anti-forensics story — what the diary says happened to the hard drive and the USB key.
- **step-07** [review_mount_plan]: 0 auto-mount candidate(s), 1 plan-only image(s) — see .atlas/mount_plan.json

High-value candidate actions:
- `evidence/RHINOUSB.dd` tool=tsk.mmls cap=disk_filesystem_timeline score=3.82 detail=summary value=4.5 est≈0 tok
- `evidence/rhino2.log` tool=strings.file_identify cap=static_file_triage score=1.7 detail=summary value=2.0 est≈0 tok
- `evidence/rhino3.log` tool=strings.file_identify cap=static_file_triage score=1.7 detail=summary value=2.0 est≈0 tok
- `evidence/rhino.log` tool=strings.file_identify cap=static_file_triage score=1.7 detail=summary value=2.0 est≈0 tok

## Investigation memory (summary)

- Validated conclusions: 0
- Active analyst context entries: 0
- Open investigation goals: 0
- Missing evidence notes: 0

## Next steps

1. Follow the Investigation Plan checklist above.
2. Call `claim.snapshot` and review needs_review / conflicts.
3. Re-examine dirty evidence and analyst-context-affected claims first,
   then expand as needed (dirty set is a start, not a boundary).
4. Update investigation task status as work progresses
   (`misc.update_investigation_task`).
5. Record each reviewed claim's outcome: `claim.revalidate` (citing the
   calls that re-read its evidence) when it still holds, `claim.supersede`
   when it does not; promote with explicit reasoning; open conflicts on
   disagreement.
6. Rewrite only affected report sections when ready.

