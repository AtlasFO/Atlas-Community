## Adversarial Review (reason.*)

Calls below are **mandatory** at the named checkpoints — not optional.

### Mandatory triggers

**`reason.hypothesize` on the case question** — at the very start of the initial Triage entry, BEFORE `reason.plan`. Pass `observation`=case question (from `CASE_QUESTION:`), `evidence`=evidence summary, `context`=full case context. The returned hypotheses are the testable propositions for the investigation. Capture each `hypothesis_id` and route findings via `tested_hypothesis_id`. For material pivot questions, run the same call with the pivot-specific question. The call's `priority_tools` carry the **discriminators that resolve the top two competing hypotheses** (logon type/source, USB serials across profiles, OneDrive/registry account bindings) — execute them as the binding work order. Resolving **every** MEDIUM+ contested principal to CONFIRMED/REFUTED or explicitly parking it as controller-unknown/evidence-unavailable is mandatory before Report, not just the leading one.

**`reason.plan`** — at the start of every Triage phase entry (initial + each pivot). Before the **initial** Triage call:
- **`misc_inventory_evidence` first** (hard gate — unlocks all other evidence work). Follow `assessment.recommended_first_actions`: consume `already_processed` exports, query tabular, skip absent classes, only then mount/path-parse `needs_processing`.
- Host-context / memory / VMDK prep reads **only when** the assessment says those classes are present and not already covered by parsed exports.
- `hash_verify_evidence_hash` on evidence files (after assessment; large evidence may sample-fingerprint)

Inventory is the only unlock for forensic tools. **Do NOT shell out to `dotnet …RECmd.dll` or `/usr/local/bin/vol`** — `source="claude_code_bash"` entries fail the cold-start gate (`protocol_violation: no_active_dair_batch`), and any finding citing them refuses via `mcp_routing`. Do not include `ewf_info`, `mmls`, `fsstat`, `vol_info` — slow and uninformative. Pass combined output as `evidence_available` (when omitted, Atlas auto-grounds from the latest successful `misc.inventory_evidence` + mount_plan summary).

For subsequent pivot Triage entries, re-check assessment / list new paths — skip host-context reads when `skip[]` or `already_processed` already covers the need.

`reason.plan` directives also inform Collect ordering — re-call mid-Collect if new findings change the picture.

**`reason.hypothesize`** — during Analyze and whenever any of these arise in **any phase**:
- Process with orphaned/ghost parent PID
- Unsigned/unknown executable on disk or in memory
- Network connection to an internal host that isn't a DC or known infra
- Scheduled task / service / Run key not present before the incident window

**`reason.evaluate_finding`** — before writing any of these phrases:
- "CONFIRMED COMPROMISE" or "attacker"
- Any TTP / threat actor attribution
- "exfiltration", "lateral movement", "persistence confirmed"
- Any negative finding used as evidence ("no injection detected", "no persistence found")

`supporting_evidence` must include the specific tool output (command + field + value) and the tier (CONFIRMED / LIKELY / SUSPECTED / UNCONFIRMED).

A CONFIRMED `record_finding` that carries its `supporting_evidence` and has no evaluation yet is evaluated by Atlas itself, on that evidence, inside the call; the result's `evaluation` field reports the verdict and the review's call id. Calling `reason.evaluate_finding` yourself is still right when you want the reviewer's weaknesses list before deciding what to record, or when you pass `case_context`.

**Automatic CHALLENGED triggers** — flag without waiting for the reviewer:
- YARA match is the sole evidence for a CONFIRMED finding
- An ATT&CK technique ID can't be verified against the finding description
- A mechanism claim has no cited raw artifact

**`reason.synthesize`** — exactly once, in the Report phase entry only (after DAIR returns `next_phase: "Report"`). Do NOT call while top-of-stack is Triage/Collect/Analyze/Scan — re-call when Report is actually reached. Pass all findings as a block.

**`reason.confidence_score`** — BEFORE `record_finding` for any tier above SUSPECTED. Pass finding text + supporting evidence + intended tier; receive an evidence-grounded tier and a 0.0–1.0 score. If returned tier is below intended, downgrade.

**`reason.cite_check`** — BEFORE `record_finding` when the finding contains concrete claims (paths, IPs, hashes, technique IDs). Returns ALL_CITED / UNCITED_CLAIMS_PRESENT / INSUFFICIENT_EVIDENCE. Resolve UNCITED_CLAIMS_PRESENT by adding citations.

**`reason.pre_report_check`** — immediately after `reason.synthesize`, before writing any report section. If `ready_to_report=False`, resolve all `blocking_issues` first. It now also **blocks** when: an unresolved distinct/second-principal hypothesis is still open; a human/account attribution verdict was recorded but no logon/RDP session inventory (4624/4625/4778/4779, or Linux `last`/`wtmp`) ran anywhere in the trace; a surfaced controller-question identity is left un-dispositioned; **`coverage.coverage_report` was never executed**; or there are 0 CONFIRMED findings with ≥2 evidence-backed LIKELY findings and fewer than 2 `reason.evaluate_finding` calls (**unevaluated under-tiering**). It also warns, without blocking, when findings that describe attack activity carry no MITRE technique (see below). **Run the logon/RDP session inventory early** (first Collect batch when event logs are in scope) so attribution closure is already satisfied at Report. A blocker the previous `reason.synthesize` already named, still standing after tool work in between, is recorded as a documented limitation instead of blocking again — whether it was written under a `BLOCKERS:` header or in prose. Open case questions block until each is closed with `misc.update_investigation_task`; the blocker lists the open task ids and the current beliefs that could answer them, so closing is one call per question. A question marked `blocked_missing_evidence` is dispositioned: it is listed for the Limitations section and does not block. The gate judges what the run **still asserts**: a claim retired with `claim.supersede` (with a successor, or with no `new_id` to withdraw it outright and a reason) is out of every check on the next pass, so a finding you cannot cite is never a permanent blocker - withdraw it or replace it with the version the evidence supports. Its trace entry remains for audit.

**`coverage.coverage_report` is mandatory before Report (blocking).** DAIR recommends it every run and it must actually run — call it once in the Report-phase entry, right after `reason.synthesize`. It maps your findings to MITRE ATT&CK and surfaces coverage gaps; it returns cleanly even for cases with no TTPs (harassment/pure-network), so it always applies. Skipping it leaves the report without any TTP mapping.

**Evaluate your strongest findings for CONFIRMED before Report.** A run that records evidence-backed findings but never calls `reason.evaluate_finding` systematically under-tiers — leaving direct, transmitted-content evidence at LIKELY. `pre_report_check` now **blocks** when there are 0 CONFIRMED findings, ≥2 LIKELY findings with direct evidence lineage, and fewer than 2 `reason.evaluate_finding` calls: adversarially evaluate at least your two strongest LIKELY findings. A SUPPORTED evaluation + citation promotes to CONFIRMED; standing by LIKELY after evaluation also clears the gate (it downgrades to a warning). Do not manufacture CONFIRMED tiers the evidence doesn't support — the goal is *correct* tiering, not maximal.

**Map MITRE techniques as you record them (advisory).** When a finding names malware, a CVE, C2/beaconing, exfiltration, **or non-malware attack activity — hacking/attack tools, packet sniffing or interception, password/hash cracking, port/network scanning, reconnaissance, brute-force** — attach validated T-IDs via `record_finding(mitre_techniques=[…])` or cite the T-ID in the description (`correlate.mitre_map` finds candidates; running it alone is not enough). `coverage.coverage_report` only *reports* coverage. `reason.pre_report_check` lists the attack findings that carry no technique, warns when three or more CONFIRMED findings carry none at all, and warns when mapped findings cluster on very few techniques; these warnings never block Report, so do not delay the report for ATT&CK labelling alone. For a genuinely TTP-less case (harassment, network attribution), state `TTPs: not applicable — <reason>` in `reason.synthesize` and the warnings stop; gap admissions like "no TTPs mapped yet" do not count.

**Never read solution material.** `Solution/`, `answers.json`, and other answer-key files in training cases are blocked at the middleware and executor level — any tool argument pointing at them is refused and traced. Findings must be re-derived from the evidence itself.

If the server is unreachable, log + note skipped checkpoints + continue.

### reason.* Parameter Reference

| Tool | Required | Optional |
|------|----------|----------|
| `reason.plan` | `case_description`, `evidence_available` (optional; auto-grounded from inventory when empty) | — |
| `reason.hypothesize` | `observation` | `evidence`, `context` |
| `reason.evaluate_finding` | `finding`, `supporting_evidence` | `case_context` |
| `reason.confidence_score` | `finding`, `supporting_evidence` | `intended_tier` |
| `reason.cite_check` | `finding`, `supporting_evidence` | — |
| `reason.synthesize` | `findings` | `investigation_summary` |
| `reason.pre_report_check` | *(none)* | — |

**`reason.hypothesize` usage:**
- `observation` — single behaviour/artifact (one sentence)
- `evidence` — raw artifact list (tool excerpts, IDs, timestamps — verbatim)
- `context` — broader case context (OS, known TTPs, timeline)
- Capture returned `hypothesis_id` (e.g. `H0007`) → pass as `tested_hypothesis_id` to any `record_finding` resolving it. Builds hypothesis→finding lineage in `trace.md`.

---
