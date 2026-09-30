## Execution Trace Log

Call `misc.start_execution_log(case_id, output_path)` at the very start, before any other tool. Path: `./analysis/<case_id>_trace.json`.

**Live-monitoring cases use per-investigation traces.** Each
alert check that finds alerts opens (or resumes) ONE
investigation, identified by an `INV-NNN` id, with its trace at
`<case>/analysis/<case>_<INV-NNN>_trace.json` (flat under
`analysis/` so the dashboard scan picks it up) and report at
`<case>/reports/<case>_<INV-NNN>.{json,md}`. All alerts drained in the
check share that one trace; new alerts arriving while it's open get
folded in via `monitor.extend_investigation`. The case-wide trace at
`analysis/<case>_trace.json` records orchestration only. The
investigation stays open across subsequent checks if response actions
are pending operator approval, so an `approve ACT-N` typed minutes
later still lands in the right trace via the `UserPromptSubmit` hook
(CLI session logging / execution trace). **Do not call
`start_execution_log` manually during this workflow** —
`monitor.start_investigation` / `extend_investigation` /
`end_investigation` manage the trace path.

Returns `dashboard_url` (live trace dashboard). **Announce it to the operator in the first message**, e.g.:
> Live trace dashboard: http://127.0.0.1:8765/reports/dashboard.html?trace=../analysis/<CASE>_trace.json

URL is also printed to stderr and written to `./analysis/dashboard.url`. Suppress with `launch_dashboard=False`.

Add `_note="<narration>"` to **one** tool call per parallel batch — middleware logs it as `agent_message` before the tool runs. Pass the same text you write to the user. For opening narration before the first tool call, use `misc_record_agent_message` directly.

```
# Example: three parallel calls, one carries the narration
vol_vol_pstree(image=..., _note="Pre-plan reads complete. Starting memory analysis.")
vol_vol_netscan(image=...)
vol_vol_cmdline(image=...)
```

Call `misc.record_finding(description, confidence, source, linked_call_id)` per confirmed finding — do not batch. Set `linked_call_id` to the `_atlas_call_id` of the source tool. Every CONFIRMED finding must have one — primary traceability link for the audit log.

**Hash artifacts at finding time (required for file-artifact findings).** When a finding names a concrete file artifact (dropped binary, malicious exe/script/maldoc, staged archive, carved file), run `hash.hash_file` on the extracted copy and cite MD5/SHA256 in the finding — that is the hash that matters for IOC sharing and intel lookups, not the hash of the surrounding disk image. `record_finding` emits a non-blocking `missing_artifact_hash_warning` when a CONFIRMED/LIKELY file-artifact finding carries no hash, so treat it as a to-do, not an option. This is the primary artifact-level custody record; it does **not** by itself substitute for image-level integrity — when the image hash was deferred (`full_hash: false`) and the engagement requires a full custody hash of the image, complete it with `verify_evidence_hash(force_full=True)` once analysis is unblocked. For an Expert Witness image (E01) the same call also returns `acquisition_hashes` - the digest the acquisition tool stored over the imaged media - and `acquisition_verified` (True when `ewfverify` re-hashed the data to it, None when the media is above the policy and was not re-hashed). That is the image-integrity statement: record it as a finding citing the call, not the segment-file hashes.

**Type the indicators at finding time (required for findings that name them).** A finding that names attacker infrastructure (addresses, domains, URLs, mail addresses), tooling or dropped files (names, paths, hashes, registry keys, services, tasks), attacker accounts or hostnames, or, on the device of the person under investigation, that person's accounts, devices and serials, credentials and key IDs, contacts and cloud resources, passes them as `indicators=[{"type": ..., "value": ..., "side": ...}]` (optional `first_seen`/`last_seen`). Sides say whose the value is: `attacker` for what the attacker brought or controls (their addresses and domains, the binaries and scripts they dropped, the accounts they created, the tools they ran), `victim` for the owner's own systems and accounts the activity touched, `subject` for the person under investigation and what is theirs, `third_party` for anyone else. The person the brief names as Subject, and their accounts, devices, mailboxes and tools, are `subject` in every frame, an insider on the owner's system included; the organisation's own documents the activity touched are `victim`. A dropped binary on the owner's host is the attacker's, not the owner's. Every value must appear in the output of a cited call; a value the cited outputs do not show is dropped and named in `indicators_dropped` while the finding still records. The indicator list (the block, hunt, scope and request items) is built from these rows, not from the prose, so a finding without them delivers no indicator; the response plan is derived from the finding's wording and names these values as its objects. `reason.pre_report_check` lists substantiated findings that should have rows and lack them; add them with `claim.add_indicators(claim_id, [...])`.

### `input_call_ids` is MANDATORY on every agent-facing record_* call

Every `misc.record_finding`, `misc.record_self_correction`, `dair.dair_assess`, and `reason.*` call MUST pass `input_call_ids=[<cid>, ...]` — the `_atlas_call_id` values of entries that informed this step. `lineage_required` refuses empty lists after the first 5 entries (genesis grace covers `start_execution_log`, pre-plan reads, first `reason.plan` / `dair_assess`). Fabricated or out-of-order ids → `unknown_cids` refusal.

This turns the trace into a self-describing causal DAG. The Process view, accuracy report, and `reason.synthesize` traverse real foreign keys instead of inferring lineage from substrings.

```python
# tool results from the prior batch had cids 17, 18, 19
dair.dair_assess(
    tool_results_summary="vol.pstree showed orphaned PID <PID>; vol.netscan flagged a beacon to <C2_IP>:<PORT>",
    phase_stack="[{\"phase\": \"Triage\", \"depth\": 0}]",
    input_call_ids=[17, 18, 19],
)

reason.evaluate_finding(
    finding="<process>.exe (PID <PID>) is a C2 beacon",
    supporting_evidence="vol.malfind PID=<PID> yields injected DLL; vol.netscan PID=<PID> → <C2_IP>:<PORT>",
    input_call_ids=[24, 31],
)

misc.record_finding(
    description="CONFIRMED C2 beacon on PID <PID> (T1055)",
    confidence="CONFIRMED",
    linked_call_id=24,                    # 1:1 primary evidence
    input_call_ids=[24, 31, 42],          # N:M complete lineage incl. supporting reason calls
)
```

`linked_call_id` (1:1 primary) and `input_call_ids` (N:M lineage) are complementary — supply both.

### Finding capture (common compliance gap)

`misc.record_agent_message` is for **reasoning and direction**, not stating facts. When you write a paragraph that contains conclusions ("CONFIRMED…", "attacker did X", "CS Beacon on PID Y", "exfiltration to IP Z", persistence/lateral-movement/credential), accompany it with structured findings — either separate `misc.record_finding(...)` calls or atomically in the same `record_agent_message`:

```python
misc.record_agent_message(
    content="<HOST> memory shows a C2 beacon on <process>.exe (PID <PID>) and an archiver staging data.",
    input_call_ids=[821, 822, 823],
    findings=[
        {"description": "<process>.exe (PID <PID>) is a C2 beacon implant on <HOST> (C2: <C2_IP>:<PORT>)",
         "confidence": "CONFIRMED", "linked_call_id": 821, "source": "vol.netscan"},
        {"description": "<archiver>.exe archived data on <HOST> in the incident window",
         "confidence": "CONFIRMED", "linked_call_id": 822, "source": "vol.cmdline"},
    ],
)
```

Each finding goes through the same gates as `misc.record_finding` (recent `dair_call`; CONFIRMED requires non-zero `linked_call_id` + recent SUPPORTED `reason.evaluate_finding`). Per-finding gate failures come back in the response; the narration entry is still written either way.

`reason.pre_report_check` runs `reason.audit_findings`, which uses the reason model (not regex) to surface narrations that mention facts but lack structured `finding` entries. Address each warning before writing the report.

After `reason.synthesize`, call `reason.pre_report_check()`. If `ready_to_report=False`, resolve all `blocking_issues` first.

Then call `misc.export_execution_log(output_path)` with path `./reports/<case_id>_trace` (no extension — both `.json` and `.md` are written).

---
