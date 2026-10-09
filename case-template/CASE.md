# Case: <CASE_ID>

**Case ID:** <CASE_ID>

**Engagement:** incident-response
<!-- incident-response: a live incident; Atlas records first-hour precautions
     (preserve, isolate, block) as recommendations for the responder.
     examination: a device or image examined after the fact; the owner's
     duties remain (each step applies to systems still in service), and a
     mitigation from the ATT&CK table is recorded as a lesson. -->

**System owner:** victim
<!-- Whose system the evidence comes from; the first word decides.
     victim: the organisation or person whose systems were attacked or
     abused; remediation is recommended to them (an insider on a company
     PC is a suspect on a victim's system: write victim).
     suspect: the device of the person under investigation; no remediation
     is recommended to its owner, investigative next steps and legal
     process apply instead.
     unknown, or the line left out: the recommendations assume a victim and
     the report says so. -->

## Investigation Requests

<!-- Append one bullet per request, for example:
- Determine whether the workstation was compromised.
- Identify the initial access vector.
- Search for persistence and staging.
-->

## What you already know

<!-- Optional. What the analyst brings to the case before any evidence is
     opened: a working theory, indicators seen elsewhere (an address from
     the firewall, a hash from an alert, an account name), a time window,
     and facts about the environment (the admin jump host, a service
     account, what normal activity looks like). One bullet per item works
     well; a pasted list or log excerpt can go in a code fence, closed by a
     line of three backticks of its own: an unclosed fence turns the rest of
     this file into code, its requests and evidence links included.
     For example:
- We suspect a ransomware intrusion that began around <date>.
- The firewall logged outbound connections from <host> to <ip>.
- The EDR alert carried the hash <sha256>.
- <ip> is our admin jump host.
     Atlas seeds searches from the indicators here, tests a theory as a
     lead, and reads a fact about the environment as context, never as an
     allowlist. Nothing in this section becomes a finding by itself, and a
     miss is never taken as proof of absence. -->

## Evidence Links

<!-- Optional but recommended: bind host names to evidence paths.
     Atlas reads this into .atlas/evidence_links.json for focus seeds.
     Kind: disk | memory | pcap | tabular | evtx | alias | principal | other -->

<!-- Example rows (copy one below the header and fill it in):
| <HOST> | disk | evidence/<HOST>/<image>.vmdk | <descriptor or E01> |
| <EDR_NAME> | alias | <HOST> | EDR device name for the same host |
| <account> | principal | | compromised account |
-->

| Label | Kind | Path | Notes |
|-------|------|------|-------|

<!--
CASE.md is the investigator work inbox — not findings, not memory, not a report.

Atlas owns investigation state under .atlas/:
  - investigation_tasks.json  (task lifecycle)
  - investigation_plan.json   (pre-execution checklist)
  - evidence_links.json       (host/path map from Evidence Links above)
  - claim_graph.json          (beliefs)
  - evidence_catalog.json     (evidence fingerprints)

Evidence: place files under ./evidence/ — Atlas discovers them automatically.
Outputs: ./analysis/, ./exports/, ./reports/ (fixed conventions).

Do not paste findings or report content here. Append investigation requests
and keep Evidence Links as a short host↔path map only.
-->
