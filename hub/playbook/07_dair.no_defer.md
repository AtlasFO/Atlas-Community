## DAIR Phase Director (dair.*)

DAIR is a **recursive state machine**, not a checklist. Outside the gated
live-monitoring `respond.*` namespace, Atlas is read-only: static-case Improve
& Response actions are never executed — only recommended in the final report.
Investigation begins with a confirmed positive detection in hand.

| Phase | Role | reason.* | Recursive? |
|-------|------|-----------|------------|
| Triage | Confirm initial IOCs, challenge hallucinations (file existence, registry keys, processes, network). Produce plan. | `reason.plan` at phase entry | Yes — new questions can be entered when relevant |
| Collect | Gather raw artifacts per plan — ez.*, vol.*, tsk.*, strings.* | `reason.plan` directives prioritize | No — advance when plan satisfied |
| Analyze | Reason about artifacts — processes, network, persistence, TTPs | `reason.hypothesize` per suspicious artifact | Yes — unexpected finding can push Triage |
| Scan | Sweep for lateral movement / other hosts — yara.*, net.*, enrich.* | — | Candidate pivots may lead back to Triage |
| Report | Synthesize timeline; emit Improve & Response recs | `reason.synthesize` + `reason.pre_report_check` | Yes — blockers return to Collect/Analyze/Scan |

**Loop anatomy:** DAIR is recursive, not linear. Any phase can discover a missing question or evidence gap; when that gap is material to the case question, return to Triage/Collect/Analyze/Scan, collect the missing evidence, then re-synthesize. Report is not a wording exercise: if `reason.synthesize` or `reason.pre_report_check` reports blockers, go back to evidence work before trying to report again.

**Candidate pivot handling.** When top-of-stack is `Scan`/`Analyze`/`Collect` and `tool_results_summary` names a **new pivot target** NOT already in `case_context` or prior `investigation_focus`, `dair_assess` may return it in `candidate_pivots` with `{kind, value, phase, cue}`. Candidate pivots are leads, not control flow. Do not mutate `phase_stack` or start a Triage solely because a candidate exists. Investigate a candidate when it is relevant to the case question, and record either a finding or an explicit out-of-scope / evidence-unavailable disposition. Two kinds of pivot target:
- **Host** — IPv4, UNC like `\\HOST\share`, or any token matching `ATLAS_PIVOT_HOSTNAME_PREFIXES` in `.env`.
- **Principal** — a newly-*created* account/identity **OR any previously-unseen identity that authenticates or first appears** (cues: an account created, a logon by an identity not seen before, a first-seen correspondent). A known identity (the case subject, or a principal already under investigation) does not re-pivot. Forced principal candidates must be dispositioned before Report. This is the structural backstop for the Distinct-Principal Discipline above.

Stop-lists filter false positives (hosts: `SCAN`/`TRIAGE`/`WINDOWS`/`SYSTEM`/AV-product/file-type tokens; principals: built-in accounts `Administrator`/`Guest`/`DefaultAccount`/`SYSTEM`/`HomeGroupUser$`/etc.).

**Context-break resumption:** If anything interrupts the investigation (context window, tool timeout, session restart, **MCP disconnect/reconnect**), the first action on resumption is `dair_assess` with the last-known phase stack — before any tool batch. If `dair_assess` is down, wait for the server. Pass `tool_results_summary="Resuming after interruption — re-establishing phase state."` and the accumulated `case_context`.

**No deferral:** forensic tools are never blocked by the DAIR window, and no deferred intent is recorded. Work through the `[work order]` shown each turn: each item is a ready call that closes when a call reads its target or fails to. Call `dair_assess` when you need a new direction or a phase change; the loop also asks the director for a review when the due reads run out or are neglected.

**Phase stack:** JSON list of `{phase, entry_reason, depth}` (newest last), maintained across calls. `stack_action`:
- `"push"` → append `{phase: next_phase, entry_reason: transition_rationale, depth: len(stack)}`
- `"pop"` → remove the top entry; resume the phase beneath
- `"stay"` → no change

**WORK-ORDER LOOP — the order carries the reads; the director sets the phase.** Every turn the `[work order]` block lists up to six due reads as ready calls, with a `[progress]` line every 20 actions.

1. Run the due reads, in order. Parallelize where independent (different hosts/artifacts).
2. Record what a read shows (`misc_record_finding`) and update the question it answers (`misc_update_investigation_task`).
3. Call `dair_assess` when the order offers nothing that leads to an answer, or for a phase change; its `priority_tools` that name a host and a path become items of the order.

The investigation ends when DAIR returns `next_phase: "Report"` and the order is settled (no due read, or the order shown for a stretch of turns without a read) — or the wall-clock backstop fires. Reads not done are listed in the report as not read.

Pass to every `dair_assess`:
- `tool_results_summary` — what the last batch found (use `"Investigation starting — no tools run yet"` on first call)
- `phase_stack` — current JSON stack (`"[]"` on first call)
- `case_context` — case ID, threat actor, confirmed IOCs so far

**Phase transitions** (on `transition_recommended: true` or `verification_satisfied: true`):
- → `Triage` (initial or new pivot): call `reason.plan` before executing `priority_tools`. Check `verification_challenges` for `verified: null` — their `challenge_method` tools appear in `priority_tools`. Call `reason.hypothesize` if any challenge resolves `verified: false`.
- → `Collect`: execute `priority_tools`; `reason.plan` directives inform order.
- → `Analyze`: execute `priority_tools`; call `reason.hypothesize` per suspicious artifact.
- → `Scan`: execute `priority_tools` (yara.*, net.*, enrich.*).
- → `pop`: sub-phase resolved — resume parent work order.
- → `Report`: call `reason.synthesize`, then `reason.pre_report_check`, then write the report **following the Final Report Contract**. Call `misc.current_investigation_state`, ensure claims have evidence refs, then **`misc.write_projected_final_report`** (required). Freeform `misc.write_final_report` is refused when beliefs exist. Include `recommended_actions` as advisory, scope-tagged per the contract. **Never perform Improve & Response.**

Log each phase transition with `_note` on the first tool call of the new batch.

**Triage max-pass cap:** Track consecutive `dair_assess` responses of `phase=Triage, stack_action=stay` (reset on `transition_recommended=True` or `verification_satisfied=True`). At count 3, force-satisfy immediately — **do not call `dair_assess` a fourth time**:
- Log: "DAIR Triage max-pass cap (3) reached — forcing transition to Collect"
- Push `{phase: "Collect", entry_reason: "max-pass cap", depth: N}` manually
- Skip `dair_assess` for the **very next batch only**. Resume normally after.

**Escape valves (server-side, not optional):** When DAIR keeps returning `stack_action=stay` without **belief** progress (`core.progress_signature.changed`), the server advances the phase. Valves are collected independently and arbitrated by specificity (more specific diagnoses win — a general productive-stall cannot shadow evidence-exhausted). Notable valves: Triage caps → Collect; `evidence_exhausted` / `empty_loop` / `productive_stall` → next phase; **refuse latch** → Report when `reason.synthesize` (or equivalent) is refused repeatedly for being outside Report. Agent-loop stall nudges use belief **plus** coverage-ledger / exploration fingerprints (`core.run_budget`); force-report / synthesize-escape requires ledger-ready or wall-clock — not belief stall alone.

**Investigation exit (Layers 2–4):** Policy lives in `core/investigation_exit.py`. Layer 2 = refuse latch (above). Layer 3 = wrap-up must not keep granting turn extensions when the READY_TO_REPORT:false blocker fingerprint is unchanged and knowledge has not progressed. Layer 4 = `misc.write_projected_final_report` writes a **degraded/partial** report with Timeline-unavailable + Limitations when CIS/timeline is incomplete — it must not hard-block the only exit path once the work order is settled (or wall-clock). `atlas_finish` banners distinguish `complete` vs `incomplete_coverage`.

---
