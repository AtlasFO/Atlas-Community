## Case-Question Anchoring

Every investigation has objectives from **CASE.md Investigation Requests**
(materialized as `.atlas/investigation_tasks.json` and seeded as `CASE_QUESTION:`).
Follow the Investigation Plan (`.atlas/investigation_plan.json`) as the
pre-execution checklist. Update task status via `misc.update_investigation_task`
as work progresses — never paste findings into CASE.md.

**What the analyst already knows (CASE.md, optional section).** A `## What you
already know` section carries the investigator's prior knowledge: a working
theory, indicators seen outside this evidence, a time window. Read it as leads,
not results. Its indicators are seeded as pivot obligations and appear in the
`[ioc pivot]` nudge — search for them in the relevant sources first. A hit is a
finding that cites the call that found it; a miss is a coverage statement,
never exoneration; the theory is a hypothesis to test with `reason.hypothesize`.
Never record the section's own content as a finding.

**Closing a question (mandatory).** A question is answered *by* beliefs, and the
answer the analyst reads is derived from exactly the beliefs you link. So:

1. Promote the belief that states the answer with `claim.promote_conclusion`
   - Record what the responder must do about it with `claim.record_recommendation` (one imperative `action`; `phase` contain|eradicate|recover|harden|investigate (a next examination step, a preservation or legal-process request)|escalate (a decision handed to others); `scope` host|network|estate; `urgency` now|soon|later; `basis_ids` = the claim/conclusion ids it rests on). Do this as findings land, not at report time: the Response view and the report's Recommendations section are projections of these nodes. An estate-scoped recommendation needs a basis beyond one host; a restatement folds into the existing one.
   (e.g. "Hands-on ransomware intrusion: encryption of 1,000 files on
   SRV-01 on 2031-02-04, preceded by DCSync-pattern replication on DC-01").
   One conclusion per question, citing the claims it rests on.
2. `misc.update_investigation_task(task_id, status="answered",
   related_claim_ids=[<conclusion id>, <supporting claim ids>])`.

`answered` / `partial` without `related_claim_ids` is refused
(`task_answer_unsupported`) and the refusal lists candidate ids. A question
whose answer is "we looked and it is not there" still links the claims that
establish the absence; a question that cannot be answered stays `partial` or
`blocked_missing_evidence` — never `answered`.

The case question MUST:
1. Appear in `case_context` as `CASE_QUESTION: <one-sentence question>` (or the
   multi-request form from open tasks).
2. Be the `observation` of an **initial `reason.hypothesize` call**, run before `reason.plan` on first Triage entry. Returned hypotheses are the testable propositions for the investigation — capture each `hypothesis_id` and route findings back via `tested_hypothesis_id`.
3. Be verified by `reason.pre_report_check` before Report — it refuses `ready_to_report` unless at least one CONFIRMED or LIKELY finding addresses the question's key entities.

For pivot-host Triage entries, re-state the case question in the pivot's `case_context` so the gates still fire.

---

## Distinct-Principal & Competing-Hypothesis Discipline (mandatory)

The most expensive investigative failure is **single-actor lock-in**: committing to one working narrative at Triage and folding every later artifact onto it — never asking whether a *second* principal is present. Guard against it:

1. **Competing hypotheses at Triage.** The initial `reason.hypothesize` on the case question MUST yield at least one hypothesis that is *not* the leading narrative — a genuinely different actor or mechanism, not an adversarial-defense strawman ("the suspect could claim account takeover"). Treat it as a live proposition and seek evidence that would confirm or kill it. **Every ranked alternative the call returns is individually tracked** (split into sub-hypotheses at the source): each contested principal at MEDIUM+ likelihood must be driven to **CONFIRMED or REFUTED** before Report — its controller established with a session/identity binding, or the alternative refuted. A *parked* ("controller unknown") or *absorbed* alternative does not count for confirmation; `reason.pre_report_check` blocks the report while a mandatory principal remains undispositioned. Pursuing only the highest-likelihood hypothesis and folding everything onto it is the single-actor lock-in this guards against.
2. **A new account/identity is a separate principal until proven otherwise.** Whenever a **newly-created or previously-unseen** account, SID, login, or identity surfaces in **any** phase — especially a privileged one, one created via removable media, or one with no preceding interactive session by a known user — you MUST:
   - run `reason.hypothesize` framing it as a *separate principal* ("who controls account X, and how did they authenticate?"), and
   - establish its controller from an **authentication/session artifact** (logon event by type + source address) **before** attributing any of its actions to anyone already in the case.
   DAIR surfaces this structurally through `candidate_pivots`: a newly-created account **or a previously-unseen identity that authenticates (interactive/RDP logon type 2/10, Security 4778/4779) or first appears as a correspondent** may be returned as a principal lead, but DAIR does not mutate the phase stack solely because a candidate exists. Treat forced principal candidates as mandatory leads: either investigate and bind them, exclude them with evidence, or explicitly park the controller as unknown. `record_finding` enforces attribution grounding too — the `principal_attribution_grounding` gate **and** `named_actor_attribution_grounding`, which also fires when a person is named directly as the actor ("Jane exfiltrated…"). `reason.pre_report_check` **blocks** Report while a distinct-principal hypothesis is unresolved or a forced surfaced identity is un-dispositioned. Do not attribute an account's actions by assumption.
3. **Re-hypothesize on divergence.** When an artifact contradicts the working hypothesis (an account created at a moment the prime subject was not active; a logon from an unexpected source; a second exfil path), re-run `reason.hypothesize` rather than absorbing the anomaly into the existing story.
4. **Physical-media initial access (mandatory when a covert account / persistence + removable media coincide).** When a covert/backdoor account or persistence is **created in an interactive/console session** AND removable media is in evidence, do **not** read "interactive session" as proof of human authorship — a **BadUSB** device injects keystrokes that are indistinguishable from typing at the logon-event level. Raise a `reason.hypothesize` framing **initial access via a physical device** ("did someone hand over or plug in a device that injected this activity?"), and run **`misc.device_install_inventory`** on `setupapi.dev.log` — it enumerates the **complete** device table and flags the structural keystroke-injector profile (a device exposing both HID/keyboard and mass-storage interfaces). **Enumerate, don't grep**: a keyword/windowed search over a bounded device-install log can silently miss a device; the structured inventory surfaces every device as a row you cannot miss. `USBSTOR`/mass-storage enumeration alone **cannot** reveal a keystroke-injection device. `record_finding`'s `interactive_injection_grounding` gate refuses the "X created it interactively" finding unless the inventory ran over the window with nothing flagged — and refuses outright if it flagged an injector.

---

## Knowns-Driven IOC Hunting (mandatory when a reference set exists)

When `case_context` includes any enumerable reference set — suspect list, user roster, asset inventory, known-good baseline, known-bad hash list, allowlist of domains/IPs — **invert the search direction**: derive query terms FROM the knowns and hunt for them in the first Triage batch, before generic enumeration.

Use `misc.knowns_pattern_generate(reference_set=[...], derivation_type=<type>)`:

| `derivation_type` | Use for | Emits |
|---|---|---|
| `person_username` | Person/account rosters ("Firstname Lastname") | jdoe, jane.doe, janedoe, doej, jane, doe, ... |
| `hostname` | Asset inventories / hostname lists | short + FQDN + apex suffix |
| `hash` | Known-bad/known-good hash lists | passes through unchanged |
| `domain` | Allowlist/denylist domain lists | exact + apex match marker |
| `exact` | Anything else | passes through unchanged |

Run the returned `ngrep_pattern` against evidence (`net.ngrep_search`, `strings.strings_grep`, `yara.scan_directory`) before broad enumeration. The first batch must include a knowns-IOC hunt when knowns exist.

---

## Identifier Cross-Reference Normalization (mandatory)

Normalize BOTH sides before declaring a non-match. Required normalizations:
- **Case folding** — compare lowercased
- **Separator equivalence** — `.` `_` `-` and absence treated as equivalent
- **Username derivations** — for person names, generate (initial+last, first.last, first_last, first+last) variants
- **Email-prefix extraction** — `user@domain.tld` matches `user`
- **Path canonicalization** — normalize separators, case (Windows), resolve `.`/`..`
- **Hash family equivalence** — match on any of MD5/SHA1/SHA256 for the same file is a match

A "no match against roster" finding must document that these normalizations were used. Surface-form-only comparison is not exhaustive.

---

## Prefer Structured Extractors Over Keyword Search

For artifacts with a known schema (HTTP cookies, registry values, event log records, MFT attributes, kernel structures), prefer the structured extractor over `ngrep` / `strings` / `grep` — keyword search discards structure and misses fields that don't textually match.

| Artifact family | Use | Instead of |
|---|---|---|
| HTTP sessions in PCAP | `net.http_session_inventory` | repeated `net.ngrep_search` for Cookie/login/email |
| Registry hive enumeration | `ez.recmd_hive`, `misc.regripper_hive` | `strings` + `grep` against hive |
| Event log fields | `misc.evtx_filter` (a first look by Event ID and time window, no .NET), `ez.evtxecmd` (`event_ids` + `time_start`/`time_end`, UTC), `misc.chainsaw_hunt` | `strings`/`grep` over the .evtx |
| **Logon sessions / source** | `ez.evtxecmd` Security **4624/4625 by logon type + source address** (Linux: `last`/`wtmp`/`sshd`) | assuming an account's actions belong to the prime subject |
| **USB device-install / BadUSB** | `misc.device_install_inventory` (complete device table from `setupapi.dev.log`) | `strings`/`grep` over `setupapi.dev.log` for a VID or time window (a search over a bounded log can silently miss a device) |
| MFT entries | `ez.mftecmd` | raw `strings` over $MFT |
| **Obfuscated scripts / encoded blobs** | `deob.decode_chain`, `deob.powershell_decode`, `deob.base64_hunt`, `deob.xor_bruteforce`, `deob.hex_decode`; Office macros → `misc.olevba_scan` | hand-rolled decoding in `misc.batch_run` python one-liners |
| **Phishing email (.eml/.msg)** | `misc.parse_email` (reconciled headers + attachment hashes) | `strings`/`python -c` over the raw `.eml` |

Keyword search only for ad-hoc lookups where no structured extractor exists, or as a confirmation pass.

**Search what you already gathered before re-running tools (`search.search_evidence`).** Every tool call's FULL output — including the truncated 90%+ of large outputs that never reached your context — is FTS-indexed per case as it runs. Before re-running an extraction to chase an IOC (hostname, IP, hash, filename, event ID), query the index: `search.search_evidence(query, tool=, time_start=, time_end=)`. Hits return the originating `call_id` — cite it as `linked_call_id`/`input_call_ids` in findings, exactly like the original tool output. FTS5 syntax: terms, `"quoted phrases"`, `AND`/`OR`/`NOT`, `a|b` alternatives. For structured CSVs (EZ Tools, SIEM exports) still prefer `table.table_query`/`table.table_pivot` — they preserve columns, FTS windows do not. `search.search_index_status` shows what is indexed so far.

**Decode with `deob.*`, not shell.** For VBScript/JScript/PowerShell, `.msc`/`.hta`/`.lnk` payloads, and base64/hex/XOR blobs, use the `deob.*` tools — they are deterministic, quoting-safe, and produce a citable `_atlas_call_id`. An ad-hoc `python -c` in `misc.batch_run` cannot be cited in a finding (the `mcp_routing` gate) and breaks easily on quoting and encoding.

**Authentication-Session Inventory before attribution (mandatory).** Whenever event logs are in scope and any persistence / lateral-movement / account-creation finding is in play, enumerate logon events **by type and source** (which account, logon type 2/3/10, source network address) *before* attributing the account's actions to a person. An account name is not a person — the binding requires a session artifact. `record_finding`'s `principal_attribution_grounding` gate refuses CONFIRMED/LIKELY account→person bindings that lack one; its sibling `named_actor_attribution_grounding` extends the same requirement to a person named directly as the actor ("Jane exfiltrated…"). This inventory is now **blocking at `reason.pre_report_check`** whenever a human/account attribution verdict is present — run it before stating who acted. Enumerate logon sessions from the **full event-log set on the mounted image** — Security 4624/4625 **and the TerminalServices channels** (LocalSessionManager / RemoteConnectionManager Operational, which record RDP type-10 logons with user + source IP and are **absent from CyLR/triage collections**) — never from the triage subset alone; a `Security.evtx` coverage gap forces a pivot to those channels / VSS / carving, never a "local-console only" conclusion (`record_finding`'s `negative_completeness` gate refuses a "no logon/RDP" negative that skipped them).

---

## Exhaustive Evidence Rule

### Never stop at the first artifact of a type
When a category can contain identity, attribution, persistence, or C2 evidence, collect ALL instances from available evidence before concluding. One example ≠ complete picture.

- **PCAP**: one HTTP cookie ≠ all cookies — extract `Cookie:` across ALL port-80 flows from the suspect device; also URL/webmail auth params (`login=`, `email=`, `user=`, `sid=`, `auth=`, and provider-specific session params); run `net.tcpdump_extract_http` + `net.tcpxtract_streams` on the device-filtered PCAP.
- **Disk**: one Run key ≠ all persistence (run all 4 Run/RunOnce hives); one browser profile ≠ all creds (check all profiles for all browsers).
- **Per-principal (every SID, including covert)**: one user's profile ≠ all the evidence. Enumerate the deleted items (**per-SID `$Recycle.Bin`**), Desktop/Downloads, staging dirs, and execution artifacts (Prefetch/UserAssist) of **every** user account on the host — including newly-created and covert accounts — not just the prime subject's. The actual exfiltrated archive and the second actor's loot routinely sit in a *different* SID's Recycle Bin / Desktop than the suspect's.
- **Memory**: run both `vol.malfind` AND `vol.hollowprocesses`; both `vol.netscan` AND `vol.netstat`.
- **Event logs**: enumerate the **full `winevt\Logs\` from the mounted image** — not just a CyLR/triage subset — including the **TerminalServices channels** (LocalSessionManager / RemoteConnectionManager Operational) that record RDP type-10 sessions with user + source IP. Check for log-clearing AND for **coverage gaps**: a log whose earliest event postdates the incident window is *silent*, not negative — pivot to VSS / carved EVTX. A "no RDP/logon" negative drawn over only `Security.evtx` is refused by `negative_completeness`.
- **USB / removable media — two forensic roles**: enumerate USB both as **egress** (USBSTOR / MountedDevices / LNK volume labels — storage that data left on) AND as **ingress / initial-access** (the `setupapi.dev.log` device-install log → HID/composite / **BadUSB** devices that inject keystrokes or autorun). For ingress, run **`misc.device_install_inventory`** on `setupapi.dev.log` — it **enumerates the complete device table** (one de-duplicated row per device: class, vendor, product, VID:PID, interfaces, first/last seen) and flags the structural keystroke-injector profile (a device exposing both HID/keyboard and mass-storage interfaces). **ENUMERATE, don't search** — do NOT `strings | grep` the log for a VID or window a `Section start`: a keyword/windowed search over a bounded log can silently miss a device (a head-capped dump; a `grep -A "Section start"` skips the device-name header line that precedes it; a hunt for an HID-composite VID misses a device whose HID install isn't separately logged). The complete inventory surfaces every device — including a mass-storage device whose vendor/product names it itself, which `USBSTOR`/mass-storage enumeration alone reads as ordinary storage. Run **both** lenses whenever removable media is in evidence — `interactive_injection_grounding` and `negative_completeness` (DEVICE_INITIAL_ACCESS) require the structured inventory (coverage spanning the window, nothing flagged) before an "X did it interactively" finding or a "no BadUSB" negative; a keyword grep no longer satisfies them.

### Identity Exhaustion Gate (all investigations)
Before writing any finding/report that states identity/attribution is unknown:
- [ ] List every artifact type in evidence that could carry identity data
- [ ] Confirm each has been queried (not just the ones that returned results first)
- [ ] Cross-reference EVERY found identity (email, username, screen name, SID, cert CN, cookie value) against any suspect list / user directory / class roster in case context
- [ ] Only then conclude "unknown — requires external legal process"

Stopping at the first found identity without checking the rest is an investigation failure. "Requires subpoenas" is valid only when the evidence is genuinely exhausted.

### Suspect list cross-reference (mandatory)
When case context includes a list of known individuals (roster, employee list, user directory, ticketing), every online identity in evidence MUST be cross-referenced before Analyze concludes. A match resolves attribution without legal process; a non-match must be explicitly noted.

### Recipient/Correspondent Exhaustion (mandatory for dissemination/exfil)
"Who received the data / who is the buyer" must be answered from a **full sender/recipient inventory** of the comms stores (mail OSTs/PSTs, chat DBs) — `misc.readpst_extract` / `misc.pff_export` then enumerate senders and recipients — **cross-referenced against the case roster**, before concluding the recipient. Do not surface an incidental/noise thread as the recipient while a named contact in the roster (or a plainly-addressed correspondent in the same mailbox) remains unchecked. The recruiter/buyer is usually addressing the subject by name in the same store you already parsed. `reason.pre_report_check` warns when a recipient is named with no evident roster cross-reference.

### Exfil-Channel Enumeration & Ranking (mandatory before the verdict)
Before stating *how* data left the host, enumerate **all** candidate channels — removable media (LNK/`MountedDevices`/USN), FTP/transfer logs, cloud-client DBs, email attachments, web upload, C2/messenger — and **rank them by evidence strength**. A channel claim requires a **transfer artifact** (bytes moved), not tool/folder presence: a file in a sync folder, a cloud-client ADS, or "the tool was installed" is **staging, not egress**. Never headline a channel in the verdict that is weaker-evidenced than a competing one. `record_finding`'s `exfil_channel_grounding` gate refuses CONFIRMED/LIKELY egress claims that cite only presence; `reason.pre_report_check` warns when multiple channels appear un-ranked.

### Email header provenance (mandatory for phishing attribution)
Attribute the sender/attacker from **`misc.parse_email`'s reconciled headers**, never from the raw `From:` alone. The visible `From:` is trivially spoofed; reconcile it against **Return-Path**, **Reply-To**, the **Message-ID** domain, the **Received** relay chain, and any **SPF/DKIM/DMARC** result before naming an attacker address. When `parse_email` flags a `header_provenance.mismatch`, treat the envelope/Received evidence as authoritative over `From:`. The victim is the recipient in the same reconciled headers.

### "Dropped file" disambiguation
Distinguish the **delivered attachment** (the lure that arrives in the email — e.g. a `.zip`/`.msc`/maldoc) from the **file dropped or downloaded during execution** (the second-stage binary written to disk or fetched from C2). Hash and attribute **each stage separately**. When a question asks for "the file the attacker dropped", it almost always means the **post-execution artifact**, not the email attachment — decode the payload chain (`deob.*`) and follow it to the binary that lands on disk before answering.

---
