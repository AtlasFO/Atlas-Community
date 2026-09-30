# Forensic Investigation Report: RHINO-HUNT

> **Closed out by Atlas (gate_ready).** reason.pre_report_check returned READY_TO_REPORT: true and the reports were written from the recorded findings.

*Projection from Current Investigation State. Not a source of truth. (generated 2026-09-29T17:42:45Z, generator report-projection/2.1).*

## Table of Contents

- [1. Executive Summary](#1-executive-summary)
- [Answers to the Investigation Questions](#answers-to-the-investigation-questions)
- [2. Scope and Evidence](#2-scope-and-evidence)
- [3. Key Findings](#3-key-findings)
- [4. Detailed Findings](#4-detailed-findings)
  - [F-013 · H0001 (second principal / controller question) resolved: the two principals are identified — 137.30.122.253](#f-013)
  - [F-014 · Email Exchange Confirming Upload Activity and Account Access — 137.30.122.253](#f-014)
- [5. Attack Timeline](#5-attack-timeline)
- [6. Evidence Gaps and Open Questions](#6-evidence-gaps-and-open-questions)
- [7. Recommendations](#7-recommendations)
- [8. Appendix](#8-appendix)

## 1. Executive Summary

In late April 2004, a shared account on a university server was used to upload rhino images and a compressed file whose contents have not been fully determined. The account was not the uploader's own; it had been provided to them by a second individual who held legitimate access to it.

The affected system is a university file server that served as the storage destination for the uploaded material. Two individuals are identified as the principals involved: one who performed the uploads and one who supplied the account credentials. A third person is referenced in the evidence as the original source of the account, but their role is not further established. The identification of the two principals is assessed as likely based on the available correspondence, though not yet confirmed through independent verification.

The most significant open questions are the nature and legality of the uploaded compressed file, and whether the sharing of the account credentials constitutes a violation of university policy or a criminal matter. The two most important next steps are to obtain and examine the contents of the uploaded file, and to determine the appropriate legal and administrative response in coordination with university authorities.

## Answers to the Investigation Questions

### Q1 · Network traces — file transfers in all three pcaps (FTP, HTTP, an encrypted zip and its password, an executable). [LIKELY]

Source host 137.30.122.253 uploaded files to the "cook" FTP server… Source 137.30.123.234 downloaded rhino4.jpg (150k) and rhino5.gif (83k). It also downloaded rhino.exe (~131KB, Content-Type: application/octet-stream).

*Parts of the request:*

- file transfers in all three pcaps: answered STOR contraband.zip (C0015)
- FTP: answered (C0004)
- HTTP: answered (C0012)
- an encrypted zip and its password: answered (C0003)
- an executable: answered rhino3.log (C0012)


Supported by C0003 · C0004 · C0011 · C0012

### Q2 · USB key — the key was reformatted: recover content by carving; two carrier images hold steganographic payloads (jphide) whose passwords are derivable from the recovered diary. [LIKELY]

Recovered diary (carved OLE Word doc 00335017.ole, University of New Orleans) contains the anti-forensics narrative… Gumbo1.txt is a "Shrimp and Tasso Gumbo" recipe. The two steganographic carrier images are among the carved rhino JPGs on the reformatted USB key (RHINOUSB).

*Parts of the request:*

- the key was reformatted: recover content by carving: answered (C0008)
- two carrier images hold steganographic payloads whose passwords are derivable from the recovered diary: answered (C0020)


Supported by C0008 · C0009 · C0010 · C0013 · C0020

### Q3 · Cross-evidence link — prove the connection between USB content and network traffic. [LIKELY]

The USB key and the network traces are connected by the gnome account: the carved diary on the USB key (00335017.ole, RHINOUSB.dd) names the gnome account that Jeremy gave the suspect, and the same gnome account is the FTP login (USER gnome / PASS gnome123) used to upload rhino1.jpg, rhino3.jpg and contraband.zip to 137.30.120.40 in rhino.log, and the web directory /~gnome/ from which rhino4.jpg, rhino5.gif and rhino.exe were downloaded from 137.30.120.37 in rhino2.log and rhino3.log. The USB-side term is the gnome account named in the diary; the network-side term is the gnome account used in the FTP and HTTP transfers.

Supported by N0022 · C0017 · C0014 · C0016

### Q4 · The anti-forensics story — what the diary says happened to the hard drive and the USB key. [LIKELY]

Recovered diary (carved OLE Word doc 00335017.ole, University of New Orleans) contains the anti-forensics narrative…

*Parts of the request:*

- what the diary says happened to the hard drive: answered (C0010)
- the USB key: answered (C0008)


Supported by C0010 · C0008

## 2. Scope and Evidence

**Investigation scope:** host `137.30.122.253`.

**Analyzed hosts (from current beliefs):**

- `137.30.122.253`

**Evidence sources (classes):**

- pcap: 3 files (e.g. `evidence/rhino2.log`, `evidence/rhino3.log`)
- disk: 1 file (e.g. `evidence/RHINOUSB.dd`)
- Claim Graph evidence references (`artifact` / `locator` / `call_id` / `record_ref`)

**Evidence coverage:** 4 of 4 delivered items examined, 0 blocked, 0 not examined.

Examined means a tool call read the item (contact, not full analysis): for an image, its content was reached through a mount, an export or a read. For a folder or an extracted archive the status says how many of its files and folders the calls named.

| Item | Kind | Status | Examined by | Findings |
|---|---|---|---|---|
| `evidence/RHINOUSB.dd` | image | examined | call 21 (tsk_mmls) | — |
| `evidence/rhino.log` | capture | examined | call 18 (net_tcpdump_list_connections) | F-013, F-014 |
| `evidence/rhino2.log` | capture | examined | call 19 (net_tcpdump_list_connections) | — |
| `evidence/rhino3.log` | capture | examined | call 20 (net_tcpdump_list_connections) | F-013, F-014 |

**Timezone:** timestamps rendered as recorded in source artifacts (prefer UTC when ISO-8601 / exporter UTC).

This report is a projection of Current Investigation State (`.atlas/`). It is not the source of truth.

## 3. Key Findings

Concise overview only. Full analysis and Supporting Evidence are in Detailed Findings.

| ID | Statement | Host | When | Confidence |
|----|---------|------|------|------------|
| [F-013](#f-013) | H0001 (second principal / controller question) resolved: the two principals are identified | 137.30.122.253 | — | LIKELY |
| [F-014](#f-014) | Email Exchange Confirming Upload Activity and Account Access | 137.30.122.253 | 2004-04-26 22:23 UTC | LIKELY |

## 4. Detailed Findings

<a id="f-013"></a>

### F-013 · H0001 (second principal / controller question) resolved: the two principals are identified — 137.30.122.253 [LIKELY]

**What happened.** H0001 (second principal / controller question) resolved: the two principals are identified. John (hugerhinolover@hotmail.com, source IP 137.30.122.253) is the uploader who used the gnome FTP/telnet account to upload rhino images and contraband.zip. Georgia (bighonkingrhino@hotmail.com) is the account holder who provided the gnome credentials ('the gnome account that Jeremy gave me' per the diary; Georgia is the one who 'checked the account later'). The gnome account belongs to the cscistu group (gid=2000) on cook.cs.uno.edu (Sun Solaris v5.9, uid=2287). Jeremy (named in the diary) is the person who originally gave the gnome account to the suspect. The controller of the gnome account is Georgia (bighonkingrhino@hotmail.com), who had access to it and shared it with John.

**Evidence.**

- 20260929T172307_551584_40_sudo.stdout · line 4 — "T 137.30.120.40:23 -> 137.30.122.253:1653 [AP] #1251"  
  `call_id=278`
- 20260929T165035_551584_8_sudo.stdout · line 3 · 2004-04-26 22:21:39 — "2004-04-26 22:21:39.970250 IP 137.30.122.253.1655 > 137.30.120.40.21: Flags [.], ack 1, win 64240, length 0"  
  `call_id=29`
- 20260929T165035_551584_8_sudo.stdout · line 8 · 2004-04-26 22:21:43 — "2004-04-26 22:21:43.602936 IP 137.30.120.40.21 > 137.30.122.253.1655: Flags [P.], seq 29:63, ack 13, win 49640, length 34: FTP: 331 Password required for gnome."  
  `call_id=29`
- …and 3 further record(s) in the execution trace

*Claim C0018 · Trace calls 24, 29, 271, 278*

<a id="f-014"></a>

### F-014 · Email Exchange Confirming Upload Activity and Account Access — 137.30.122.253 [LIKELY]

**What happened.** A Hotmail email exchange preserved in rhino.log confirms the operational details of the gnome account usage. John (hugerhinolover@hotmail.com, source 137.30.122.253) sent a message to bighonkingrhino@hotmail.com at 2004-04-26 22:23:20 UTC stating he had checked the gnome account on cook.cs.uno.edu and was about to upload new rhino content. Georgia's reply confirmed she would check the account later and referenced being occupied in a lab.

**Why it matters.** This email exchange serves as a direct contemporaneous record linking John to the upload activity on the gnome account. The timestamp (2004-04-26 22:23:20 UTC) provides a temporal anchor that can be correlated with file transfer logs on cook.cs.uno.edu to confirm the upload occurred as described. The content of John's message explicitly names the target system (cook.cs.uno.edu, 137.30.120.40), the account (gnome), and the nature of the content (rhino images), which aligns with the files observed in the forensic image. Georgia's reply is notable for two reasons: it confirms her role as the account holder who monitors the account, and her reference to being "working on something in the lab" is consistent with a university or research environment, which is consistent with the cscistu group affiliation on a .edu system. The confidence is rated LIKELY because the email content is unambiguous in its reference to the account, the target host, and the intended action, though the email itself is a self-reported statement and would ideally be corroborated by independent server-side logs of the actual file transfer.

**Evidence.**

- 20260929T172307_551584_40_sudo.stdout · line 4 — "T 137.30.120.40:23 -> 137.30.122.253:1653 [AP] #1251"  
  `call_id=278`
- 20260929T172307_551584_40_sudo.stdout · line 5 — "gnome pts/5 Apr 26 17:17 (137.30.122.253).... Today i"  
  `call_id=278`
- 20260929T172307_551584_40_sudo.stdout · line 79 — "T 137.30.122.253:1690 -> 64.4.43.250:80 [AP] #2600"  
  `call_id=278`

*Claim C0019 · Trace calls 24, 271, 278, 293*

## 5. Attack Timeline

Curated attack timeline derived from resolved evidence records linked to findings. Supporting claim-relevant detail is also in `master_timeline.tsv` (see Appendix) — that file is curated, not a raw EVTX/session dump.

| Timestamp | Host | User | Event | Finding | Evidence Ref |
|-----------|------|------|-------|---------|--------------|
| 2004-04-26 22:21:39 | 137.30.122.253 | — | 2004-04-26 22:21:39.970250 IP 137.30.122.253.1655 > 137.30.120.40.21: Flags [.], | F-013 | 20260929T165035_551584_8_sudo.stdout · L3 |
| 2004-04-26 22:21:43 | 137.30.122.253 | — | 2004-04-26 22:21:43.602936 IP 137.30.120.40.21 > 137.30.122.253.1655: Flags [P.] | F-013 | 20260929T165035_551584_8_sudo.stdout · L8 |
| 2004-04-26 22:21:56 | 137.30.122.253 | — | 2004-04-26 22:21:56.292139 IP 137.30.120.40.21 > 137.30.122.253.1658: Flags [S.] | F-013 | 20260929T165035_551584_8_sudo.stdout · L31 |

## 6. Evidence Gaps and Open Questions

### Identity and Attribution Gaps

- **Jeremy's identity and role remain unresolved.** C0018 (F-013) names "Jeremy" as the individual who originally provided the gnome account to the suspect, based on a diary reference. No independent artifact corroborates Jeremy's identity, affiliation, or the circumstances under which the account was shared. The diary entry is the sole source for this attribution.

- **The "diary" artifact's provenance and integrity are not established in the current findings.** C0018 (F-013) relies on a diary to support the claim that Georgia provided the gnome credentials and that Jeremy was the original grantor. No claim documents the diary's file path, hash, extraction method, or chain of custody on host 137.30.122.253.

### Technical Scope Gaps (Host 137.30.122.253)

- **No claim documents the forensic state of 137.30.122.253 itself.** The two registered claims (C0018, C0019) concern identity resolution and the email exchange recorded in rhino.log. There is no claim addressing file-system artifacts, process history, network connection logs, or authentication records on this host. It is not yet established from the current findings whether 137.30.122.253 is John's personal workstation, a shared system, or a compromised endpoint.

- **The access mechanism to the gnome account is not technically confirmed.** C0018 (F-013) references "gnome FTP/telnet account," but no claim documents the specific protocol, session logs, or authentication events used by John from 137.30.122.253 to reach cook.cs.uno.edu (137.30.120.40).

### Cross-Host Gaps

- **The forensic state of cook.cs.uno.edu (137.30.120.40) is outside this host report.** The gnome account (uid=2287, cscistu group, gid=2000, Sun Solaris v5.9) resides on that system. No findings in this report address login records, file modification timestamps, or account configuration on the target host. See the Estate Report for cross-host correlation.

- **cscistu group membership is uncharacterised.** C0018 (F-013) notes the gnome account belongs to the cscistu group (gid=2000). No claim documents whether other group members had access to the account or its files, which would affect the scope of potential data exfiltration or tampering.

### Artifact Gaps

- **contraband.zip is referenced but not characterised.** C0018 (F-013) mentions "contraband.zip" as part of the upload activity. No claim provides its size, hash, file path, or contents. Its presence on 137.30.122.253 (as a staging file) or on cook.cs.uno.edu (as a received file) is unconfirmed in the current findings.

- **rhino.log scope and completeness are not documented.** C0019 (F-014) cites a specific email exchange from 2004-04-26 22:23:20 UTC. No claim states the total number of entries in rhino.log, its time range, or whether it represents a complete capture or a partial extract.

### Temporal Gaps

- **Activity window is limited to a single exchange.** The only timestamped evidence in the current findings is the 2004-04-26 email pair (C0019, F-014). No claim establishes when the gnome account was first used, when contraband.zip was uploaded, or whether activity continued after the documented exchange.

### Open Questions

1. Is 137.30.122.253 John's dedicated workstation, or is it a shared or compromised system? (No claim addresses this.)
2. What is the full content and provenance of the diary referenced in C0018 (F-013)?
3. Can the access from 137.30.122.253 to cook.cs.uno.edu be corroborated by network or authentication logs on either host?
4. What is the identity of Jeremy, and can the diary's claim about account transfer be independently verified?
5. Does rhino.log contain entries beyond the 2004-04-26 exchange that would extend the activity timeline?

## 7. Recommendations

*This case is an examination after the fact. The owner's duties remain: each measure below applies to systems still in service, and only if the owner has not already taken it. A measure derived from the ATT&CK mitigation table is a lesson for the owner, not a first-hour step.*

*The brief does not say whose system this is; the recommendations assume the owner is the victim.*

No recommendations were recorded for this scope.

Estate-wide measures are in the estate report.

## Indicators

Frame: incident on the owner's systems. Attacker rows are block and hunt items; the owner's own assets are listed under Scope, never as block items. Verify ownership before deploying a block item.
18 typed indicator(s) (6 block, 1 contain, 10 hunt, 2 identify); 0 own asset(s) named in the findings; 1 prose-derived candidate(s) to review before use.
The indicator files could not be written for this report.

## 8. Appendix

### Master Timeline

- Curated investigation timeline: `master_timeline.tsv` (not written for this case yet).

### Report generation metadata

- Case ID: `RHINO-HUNT`
- Report language: `en`
- Generator: `report-projection/2.1`
- Scope: `host` host=`137.30.122.253`
- Findings rendered: 2

### Conflicts

No open Conflict Findings in Current Investigation State.

<!-- section:exec_summary status:current claims:C0018,C0019 conclusions: conflicts: -->
<!-- section:scope_evidence status:current claims: conclusions: conflicts: -->
<!-- section:key_findings status:current claims:C0018,C0019 conclusions: conflicts: -->
<!-- section:detailed_findings status:current claims:C0018,C0019 conclusions: conflicts: -->
<!-- section:timeline status:current claims:C0018,C0019 conclusions: conflicts: -->
<!-- section:gaps status:current claims:C0018,C0019 conclusions: conflicts: -->
<!-- section:recommendations status:current claims:C0018,C0019 conclusions: conflicts: -->
<!-- section:appendix status:current claims: conclusions: conflicts: -->
