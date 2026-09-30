## Negative findings (UNCONFIRMED tier)

"We looked for X and found nothing" is real work. Record it:
```
misc.record_finding(
    description="No persistence via HKLM\\Run keys — searched all 4 Run/RunOnce hives via RECmd",
    confidence="UNCONFIRMED",
    source="ez.recmd",
    linked_call_id=<tool_call_id>,
)
```
The accuracy framework scores negative assertions in `ground_truth.json` against these UNCONFIRMED findings → `negative_coverage` metric.

**Completeness is enforced (`negative_completeness` gate).** A negative is valid only over the COMPLETE source set for its claim — absence from the subset you happened to search is not evidence of absence (the closed-world-over-open-world failure). For a case-inverting category (logon/auth, identity, persistence, exfil) `record_finding` refuses an UNCONFIRMED finding unless the trace searched **every** source in the category manifest AND a searched log's coverage window spans the claim's time window. Concretely: a "no RDP/logon", "controller unknown", or "local-console only" claim requires the **TerminalServices channels** (LocalSessionManager / RemoteConnectionManager Operational — on the **full `winevt\Logs\` of the mounted image, NOT the CyLR/triage set**), not just `Security.evtx`; and if `Security.evtx` coverage *starts after* the claim window, that silence is **not** a negative — pivot to TS logs / VSS / carved EVTX. Either search the missing sources or record an explicit "<source> absent from evidence" finding.

**Temporal negatives are enforced (`temporal_negative_grounding` gate, ANY tier).** "No activity after <date>", "system last active on <date>", "dormant/offline since <date>" claims are report-inverting: they must be corroborated by **at least two independent artifact classes** (event logs; MFT/USN; registry; prefetch/SRUM; plaso timeline) that were *successfully* examined — missing, empty, or timed-out tool output is an **analysis problem, never evidence of system inactivity**. And when the evidence is a snapshotted VMDK, the claim is refused outright if the trace only read the frozen base extent. Explicitly search the window between the claimed last-activity date and the collection date before asserting silence.

---
