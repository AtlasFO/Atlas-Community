# Forensic Investigation Report: RHINO-HUNT

> **Closed out by Atlas (gate_ready).** reason.pre_report_check returned READY_TO_REPORT: true and the reports were written from the recorded findings.

*Projection from Current Investigation State. Not a source of truth. (generated 2026-09-29T17:42:05Z, generator report-projection/2.1).*

## Table of Contents

- [1. Executive Summary](#1-executive-summary)
- [Answers to the Investigation Questions](#answers-to-the-investigation-questions)
- [2. Scope and Evidence](#2-scope-and-evidence)
- [3. Key Findings](#3-key-findings)
- [4. Detailed Findings](#4-detailed-findings)
  - [F-017 · gnome Account as Cross-Evidence Identifier (Conclusion) — RHINOUSB](#f-017)
  - [F-001 · Source host 137.30.122.253 opened a telnet connection to 137.30.120.40:23 at 2004-04-26 22:20:23 UTC… — RHINOUSB](#f-001)
  - [F-002 · FTP Upload of Rhino Images and Encrypted Archive — RHINOUSB](#f-002)
  - [F-003 · USB Key Reformat (Superfloppy, No Partition Table) — RHINOUSB](#f-003)
  - [F-004 · Decoy Files on Reformatted USB Key — RHINOUSB](#f-004)
  - [F-005 · Carved Diary: Anti-Forensics Narrative — RHINOUSB](#f-005)
  - [F-006 · HTTP Download of rhino4.jpg and rhino5.gif — RHINOUSB](#f-006)
  - [F-007 · HTTP Download of rhino.exe — RHINOUSB](#f-007)
  - [F-008 · Steganographic Carrier Images: Extraction Limitation — RHINOUSB](#f-008)
  - [F-009 · Cross-Evidence Link: gnome Account (Initial) — RHINOUSB](#f-009)
  - [F-010 · Encrypted ZIP: contraband.zip — RHINOUSB](#f-010)
  - [F-011 · Cross-Evidence Link: gnome Account (Detailed) — RHINOUSB](#f-011)
  - [F-012 · Cross-Evidence Relation: gnome Account (Summary) — RHINOUSB](#f-012)
  - [F-015 · Steganographic Carrier Images: Tooling Limitation (Detailed) — RHINOUSB](#f-015)
- [5. Attack Timeline](#5-attack-timeline)
- [6. Evidence Gaps and Open Questions](#6-evidence-gaps-and-open-questions)
- [7. Recommendations](#7-recommendations)
- [8. Appendix](#8-appendix)

## 1. Executive Summary

In late April 2004, a suspect possessed and attempted to conceal illegal wildlife images (rhinoceros photographs) on a USB key and a hard drive. The suspect reformatted the USB key to destroy the images and, according to a personal diary recovered from the key, destroyed the hard drive and discarded it in the Mississippi River. Network records show that on April 26 and April 28, 2004, the suspect used a shared account — provided by a person identified only as "Jeremy" — to upload and download the same rhino images and an encrypted archive between two network hosts.

The USB key was the primary evidence item. Its live contents consisted only of two unrelated recipe files, which investigators assessed as deliberate decoys. The actual diary and rhino images were recovered from unallocated space on the key. The diary confirms the suspect's awareness that the images were illegal and documents the steps taken to destroy evidence. The network traces confirm that the same account named in the diary was used to transfer the rhino images and an encrypted file over the network, linking the USB content to the network activity with high confidence.

Two items remain unresolved. First, two of the recovered images appear to contain hidden data embedded using a steganography tool, but the specific version of the tool used is not supported by the extraction software available to the investigation team; the hidden payloads have not been recovered. Second, the encrypted archive uploaded over the network contains a file that appears to be another rhino image, but its full contents could not be verified due to a size discrepancy in the recovered data. The most important next steps are to obtain a compatible steganography extraction tool to recover the hidden payloads, and to identify the individual known as "Jeremy" who provided the shared account.

## Answers to the Investigation Questions

### Q1 · Network traces — file transfers in all three pcaps (FTP, HTTP, an encrypted zip and its password, an executable). [LIKELY]

Source host 137.30.122.253 uploaded files to the "cook" FTP server… Source 137.30.123.234 downloaded rhino4.jpg (150k) and rhino5.gif (83k)… Source 137.30.123.234 downloaded rhino.exe (~131KB, Content-Type: application/octet-stream)…

*Parts of the request:*

- file transfers in all three pcaps: answered STOR contraband.zip (F-010)
- FTP: answered (F-002)
- HTTP: answered (F-007)
- an encrypted zip and its password: answered (F-001)
- an executable: answered rhino3.log (F-007)


Supported by F-001 · F-002 · F-006 · F-007

### Q2 · USB key — the key was reformatted: recover content by carving; two carrier images hold steganographic payloads (jphide) whose passwords are derivable from the recovered diary. [LIKELY]

Recovered diary (carved OLE Word doc 00335017.ole, University of New Orleans) contains the anti-forensics narrative… Gumbo1.txt is a "Shrimp and Tasso Gumbo" recipe. The two steganographic carrier images are among the carved rhino JPGs on the reformatted USB key (RHINOUSB).

*Parts of the request:*

- the key was reformatted: recover content by carving: answered (F-003)
- two carrier images hold steganographic payloads whose passwords are derivable from the recovered diary: answered (F-015)


Supported by F-003 · F-004 · F-005 · F-008 · F-015

### Q3 · Cross-evidence link — prove the connection between USB content and network traffic. [LIKELY]

The USB key and the network traces are connected by the gnome account: the carved diary on the USB key (00335017.ole, RHINOUSB.dd) names the gnome account that Jeremy gave the suspect, and the same gnome account is the FTP login (USER gnome / PASS gnome123) used to upload rhino1.jpg, rhino3.jpg and contraband.zip to 137.30.120.40 in rhino.log, and the web directory /~gnome/ from which rhino4.jpg, rhino5.gif and rhino.exe were downloaded from 137.30.120.37 in rhino2.log and rhino3.log. The USB-side term is the gnome account named in the diary; the network-side term is the gnome account used in the FTP and HTTP transfers.

Supported by F-017 · F-012 · F-009 · F-011

### Q4 · The anti-forensics story — what the diary says happened to the hard drive and the USB key. [LIKELY]

Recovered diary (carved OLE Word doc 00335017.ole, University of New Orleans) contains the anti-forensics narrative…

*Parts of the request:*

- what the diary says happened to the hard drive: answered (F-005)
- the USB key: answered (F-003)


Supported by F-005 · F-003

## 2. Scope and Evidence

**Investigation scope:** host `RHINOUSB`.

**Analyzed hosts (from current beliefs):**

- `RHINOUSB`

**Evidence sources (classes):**

- pcap: 3 files (e.g. `evidence/rhino2.log`, `evidence/rhino3.log`)
- disk: 1 file (e.g. `evidence/RHINOUSB.dd`)
- Claim Graph evidence references (`artifact` / `locator` / `call_id` / `record_ref`)

**Evidence coverage:** 4 of 4 delivered items examined, 0 blocked, 0 not examined.

Examined means a tool call read the item (contact, not full analysis): for an image, its content was reached through a mount, an export or a read. For a folder or an extracted archive the status says how many of its files and folders the calls named.

| Item | Kind | Status | Examined by | Findings |
|---|---|---|---|---|
| `evidence/RHINOUSB.dd` | image | examined | call 21 (tsk_mmls) | F-003, F-004, F-005, F-015 |
| `evidence/rhino.log` | capture | examined | call 18 (net_tcpdump_list_connections) | F-017, F-001, F-002, F-009, F-010, F-011, F-012 |
| `evidence/rhino2.log` | capture | examined | call 19 (net_tcpdump_list_connections) | F-017, F-006, F-008, F-009, F-011, F-012 |
| `evidence/rhino3.log` | capture | examined | call 20 (net_tcpdump_list_connections) | F-017, F-007, F-009, F-010, F-011, F-012 |

**Timezone:** timestamps rendered as recorded in source artifacts (prefer UTC when ISO-8601 / exporter UTC).

This report is a projection of Current Investigation State (`.atlas/`). It is not the source of truth.

## 3. Key Findings

Concise overview only. Full analysis and Supporting Evidence are in Detailed Findings.

| ID | Statement | Host | When | Confidence |
|----|---------|------|------|------------|
| [F-017](#f-017) | gnome Account as Cross-Evidence Identifier (Conclusion) | RHINOUSB | — | LIKELY |
| [F-001](#f-001) | Source host 137.30.122.253 opened a telnet connection to 137.30.120.40:23 at 2004-04-26 22:20:23 UTC… | RHINOUSB | 2004-04-26 22:20 UTC | LIKELY |
| [F-002](#f-002) | FTP Upload of Rhino Images and Encrypted Archive | RHINOUSB | 2004-04-26 22:21 UTC | LIKELY |
| [F-003](#f-003) | USB Key Reformat (Superfloppy, No Partition Table) | RHINOUSB | — | LIKELY |
| [F-004](#f-004) | Decoy Files on Reformatted USB Key | RHINOUSB | — | LIKELY |
| [F-005](#f-005) | Carved Diary: Anti-Forensics Narrative | RHINOUSB | — | LIKELY |
| [F-006](#f-006) | HTTP Download of rhino4.jpg and rhino5.gif | RHINOUSB | 2004-04-28 21:08 UTC | LIKELY |
| [F-007](#f-007) | HTTP Download of rhino.exe | RHINOUSB | 2004-04-28 21:16 UTC | LIKELY |
| [F-008](#f-008) | Steganographic Carrier Images: Extraction Limitation | RHINOUSB | — | SUSPECTED |
| [F-009](#f-009) | Cross-Evidence Link: gnome Account (Initial) | RHINOUSB | — | LIKELY |
| [F-010](#f-010) | Encrypted ZIP: contraband.zip | RHINOUSB | 2004-04-26 22:26 UTC | LIKELY |
| [F-011](#f-011) | Cross-Evidence Link: gnome Account (Detailed) | RHINOUSB | — | LIKELY |
| [F-012](#f-012) | Cross-Evidence Relation: gnome Account (Summary) | RHINOUSB | — | LIKELY |
| [F-015](#f-015) | Steganographic Carrier Images: Tooling Limitation (Detailed) | RHINOUSB | — | SUSPECTED |

## 4. Detailed Findings

<a id="f-017"></a>
<a id="f-016"></a>

### F-017 · gnome Account as Cross-Evidence Identifier (Conclusion) — RHINOUSB [LIKELY]

**What happened.** The USB key and the network traces are connected by the gnome account: the carved diary on the USB key (00335017.ole, RHINOUSB.dd) names the gnome account that Jeremy gave the suspect, and the same gnome account is the FTP login (USER gnome / PASS gnome123) used to upload rhino1.jpg, rhino3.jpg, and contraband.zip to 137.30.120.40 in rhino.log, and the web directory /~gnome/ from which rhino4.jpg, rhino5.gif, and rhino.exe were downloaded from 137.30.120.37 in rhino2.log and rhino3.log. The USB-side term is the gnome account named in the diary; the network-side term is the gnome account used in the FTP and HTTP transfers.

**Why it matters.** This is the formal conclusion (N0022) of the investigation regarding the cross-evidence relation. The gnome account is the single identifier that appears on both sides of the evidence boundary: it is named in the carved diary on the USB key (USB-side) and it is the credential used in the FTP upload (rhino.log) and the web directory served in the HTTP downloads (rhino2.log, rhino3.log) (network-side). This directly answers the case question regarding how the USB content and network traffic are connected. The relation is an identity, not a correlation: the same account name, the same contraband (rhino images), and the same actor. The evidence is internally consistent, mutually reinforcing, and free of contradictions. No gaps are noted. The confidence is LIKELY rather than CONFIRMED because the diary is a self-authored document (the suspect's own words) and could theoretically be fabricated; however, the independent network traces corroborate the account's use, making fabrication unlikely.

**Evidence.**

- 20260929T165035_551584_8_sudo.stdout · line 6 · 2004-04-26 22:21:43 — "2004-04-26 22:21:43.598613 IP 137.30.122.253.1655 > 137.30.120.40.21: Flags [P.], seq 1:13, ack 29, win 64212, length 12: FTP: USER gnome"  
  `call_id=29`
- 20260929T165035_551584_8_sudo.stdout · line 3 · 2004-04-26 22:21:39 — "2004-04-26 22:21:39.970250 IP 137.30.122.253.1655 > 137.30.120.40.21: Flags [.], ack 1, win 64240, length 0"  
  `call_id=29`
- 20260929T165035_551584_8_sudo.stdout · line 34 · 2004-04-26 22:21:56 — "2004-04-26 22:21:56.599918 IP 137.30.122.253.1658 > 137.30.120.40.21: Flags [.], ack 29, win 64212, length 0"  
  `call_id=29`
- …and 3 further record(s) in the execution trace

*Claim N0022 · also recorded as F-016 · Trace calls 29, 278, 279, 280*

<a id="f-001"></a>

### F-001 · Source host 137.30.122.253 opened a telnet connection to 137.30.120.40:23 at 2004-04-26 22:20:23 UTC… — RHINOUSB [LIKELY]

**What happened.** Telnet session in rhino.log: source host 137.30.122.253 opened a telnet connection to 137.30.120.40:23 at 2004-04-26 22:20:23 UTC (terminal type ANSI). This is the telnet channel referenced in the case question; the interactive payload is being extracted to identify who granted the FTP/telnet account.

**Evidence.**

- 2004-04-26 22:20:23 — "137.30.122.253 :: 2004-04-26 22:20:23.576821 IP 137.30.122.253.1653 > 137.30.120.40.23: Flags [S], seq"  
  `call_id=30`
- 20260929T165035_551584_9_sudo.stdout · line 5 · 2004-04-26 22:20:23 — "2004-04-26 22:20:23.606302 IP 137.30.122.253.1653 > 137.30.120.40.23: Flags [P.], seq 1:7, ack 16, win 64225, length 6 [telnet WILL TERMINAL TYPE, WILL NAWS]"  
  `call_id=30`
- 20260929T165035_551584_9_sudo.stdout · line 10 · 2004-04-26 22:20:23 — "2004-04-26 22:20:23.607027 IP 137.30.122.253.1653 > 137.30.120.40.23: Flags [P.], seq 25:28, ack 34, win 64207, length 3 [telnet WONT XDISPLOC]"  
  `call_id=30`
- …and 3 further record(s) in the execution trace

*Claim C0003 · Trace calls 30*

<a id="f-002"></a>

### F-002 · FTP Upload of Rhino Images and Encrypted Archive — RHINOUSB [LIKELY]

**What happened.** Source host 137.30.122.253 uploaded three files to the "cook" FTP server at 137.30.120.40:21 using the account USER gnome / PASS gnome123. The uploaded files were rhino1.jpg (65,703 bytes), rhino3.jpg (193,797 bytes), and contraband.zip (230,566 bytes). The session spanned 2004-04-26 22:21–22:26 UTC and is recorded in rhino.log.

**Why it matters.** This FTP transfer is the primary exfiltration event in the network evidence. The use of the gnome account (password gnome123) directly links this transfer to the USB-side evidence: the carved diary on the reformatted USB key explicitly names the gnome account as one "Jeremy gave" the suspect. The three uploaded files constitute the contraband the diary references — rhino images and an encrypted archive (contraband.zip, which contains rhino2.jpg per F-010). The temporal proximity to the telnet session (F-001) indicates a deliberate, sequenced operation: authenticate via telnet, then upload via FTP. The source IP 137.30.122.253 is the actor's workstation. No uncertainty is noted in the claim itself; the transfer is fully captured in the pcap.

**Evidence.**

- 20260929T165035_551584_8_sudo.stdout · line 6 · 2004-04-26 22:21:43 — "2004-04-26 22:21:43.598613 IP 137.30.122.253.1655 > 137.30.120.40.21: Flags [P.], seq 1:13, ack 29, win 64212, length 12: FTP: USER gnome"  
  `call_id=29`
- 20260929T165035_551584_8_sudo.stdout · line 37 · 2004-04-26 22:21:59 — "2004-04-26 22:21:59.487820 IP 137.30.120.40.21 > 137.30.122.253.1658: Flags [P.], seq 29:63, ack 13, win 49640, length 34: FTP: 331 Password required for gnome."  
  `call_id=29`
- 20260929T165035_551584_8_sudo.stdout · line 4 · 2004-04-26 22:21:39 — "2004-04-26 22:21:39.998180 IP 137.30.120.40.21 > 137.30.122.253.1655: Flags [P.], seq 1:29, ack 1, win 49640, length 28: FTP: 220 cook FTP server ready."  
  `call_id=29`
- …and 3 further record(s) in the execution trace

*Claim C0004 · Trace calls 29*

<a id="f-003"></a>

### F-003 · USB Key Reformat (Superfloppy, No Partition Table) — RHINOUSB [LIKELY]

**What happened.** The USB key RHINOUSB.dd was reformatted as a superfloppy with no partition table. Its live filesystem contains only two files: gumbo1.txt (inode 4) and gumbo2.txt (inode 6). The rhino images and other previously stored content were destroyed by the reformat and must be recovered from unallocated space by carving.

**Why it matters.** The reformat is a deliberate anti-forensic action consistent with the diary's statement that the suspect intended to "reformat my USB key after this entry, but try not to destroy the good stuff." The superfloppy layout (no partition table) is characteristic of a low-level format or a format performed with a tool that does not create a partition structure. The fact that only two small text files remain in the live filesystem while the bulk of the data (rhino JPGs, the OLE diary document, stego carriers) resides in unallocated space confirms that the reformat was performed to obscure the filesystem metadata while the underlying data blocks remained intact. Carving was therefore the appropriate recovery method. No uncertainty is noted.

**Evidence.**

- source not identified — "no partition table: the image carries no volume system. Read it as a single filesystem — tsk.fsstat / tsk.fls on the image without an offset."  
  `call_id=21`
- gumbo1.txt · line 1 — "r/r 4: gumbo1.txt"  
  `call_id=26`
- gumbo2.txt · line 2 — "r/r 6: gumbo2.txt"  
  `call_id=26`
- …and 4 further record(s) in the execution trace

*Claim C0008 · Trace calls 21, 26*

<a id="f-004"></a>

### F-004 · Decoy Files on Reformatted USB Key — RHINOUSB [LIKELY]

**What happened.** The two live files on the reformatted USB key are decoys, not the diary. gumbo1.txt is a "Shrimp and Tasso Gumbo" recipe (Gourmet, June 2005) and gumbo2.txt is a "Shrimp and Andouille Sausage Gumbo" recipe (Bon Appétit, November 1992). The "gumbo" filenames are a red herring. The actual diary, rhino images, and stego carrier images reside in unallocated space and must be recovered by carving.

**Why it matters.** The decoy files serve a dual purpose: they provide plausible deniability (the USB key appears to contain only cooking recipes) and they supply a password candidate ("gumbo") for the steganographic carriers and the encrypted ZIP. The choice of two different gumbo recipes from different publications (Gourmet 2005, Bon Appétit 1992) suggests the suspect selected them specifically for the keyword "gumbo" rather than for any culinary interest. This is consistent with the diary's narrative of deliberate anti-forensic preparation. The decoys do not contain any incriminating content themselves; their forensic value is as a password source and as evidence of premeditation. No uncertainty is noted.

**Evidence.**

- gumbo1.txt · line 1 — "Output written to /home/analyst/cases/RHINO-HUNT/analysis/gumbo1.txt"  
  `call_id=27`
- gumbo2.txt · line 1 — "Output written to /home/analyst/cases/RHINO-HUNT/analysis/gumbo2.txt"  
  `call_id=28`

*Claim C0009 · Trace calls 27, 28*

<a id="f-005"></a>

### F-005 · Carved Diary: Anti-Forensics Narrative — RHINOUSB [LIKELY]

**What happened.** The recovered diary (carved OLE Word document 00335017.ole, University of New Orleans) contains an explicit anti-forensics narrative. The suspect states that they deleted the rhino photos, zapped the hard drive and threw it into the Mississippi River, and intended to reformat the USB key. The diary also names the gnome account as one "Jeremy gave" the suspect and notes the intent to change its password at Radio Shack.

**Why it matters.** This document is the single most important piece of evidence in the case. It establishes three critical facts: (a) the hard drive was destroyed and discarded in the Mississippi River, explaining why no local disk image is available; (b) the USB key was reformatted to hide the rhino images, which is confirmed by the filesystem state in F-003; and (c) the gnome account was provided by a third party named Jeremy, establishing a potential accomplice or enabler. The diary's tone ("Makes me sick," "Things are getting a little weird") indicates the suspect was aware of the legal risk and was actively taking steps to destroy evidence. The reference to changing the password at Radio Shack suggests the suspect had not yet done so at the time of writing, which is consistent with the network traces showing the original password (gnome123) still in use. No uncertainty is noted in the claim.

**Evidence.**

- source not identified — "Default Paragraph Font"  
  `call_id=62`
- source not identified — "Table Normal"  
  `call_id=62`
- source not identified — "Times New Roman"  
  `call_id=62`
- …and 3 further record(s) in the execution trace

*Claim C0010 · Trace calls 53, 62*

<a id="f-006"></a>

### F-006 · HTTP Download of rhino4.jpg and rhino5.gif — RHINOUSB [LIKELY]

**What happened.** Source host 137.30.123.234 downloaded rhino4.jpg (150 KB) and rhino5.gif (83 KB) from the /~gnome/ web directory on 137.30.120.37:80 at 2004-04-28 21:08:38 UTC. The directory listing showed both files dated 28-Apr-2004 16:09. This is recorded in rhino2.log.

**Why it matters.** This HTTP session represents a second phase of the actor's network activity, occurring approximately two days after the FTP upload (F-002). The source IP 137.30.123.234 differs from the FTP source (137.30.122.253), which may indicate the actor used a different machine or network location, or that the IP changed. The files were served from the /~gnome/ directory, again tying the network activity to the gnome account. The file dates (28-Apr-2004 16:09) precede the download time (21:08:38 UTC), indicating the files were uploaded to the web server earlier that day. The download of additional rhino images (rhino4.jpg, rhino5.gif) suggests the actor was collecting or distributing the full set of contraband across multiple channels. No uncertainty is noted.

**Evidence.**

- 20260929T165905_551584_17_sudo.stdout · line 31 · 2004-04-28 21:08:38 — "2004-04-28 21:08:38.104863 IP 137.30.123.234.2026 > 137.30.120.37.80: Flags [.], ack 8430, win 64240, length 0"  
  `call_id=86`
- 20260929T165905_551584_17_sudo.stdout · line 37 · 2004-04-28 21:08:38 — "2004-04-28 21:08:38.111439 IP 137.30.123.234.2026 > 137.30.120.37.80: Flags [.], ack 14270, win 64240, length 0"  
  `call_id=86`
- 20260929T165905_551584_17_sudo.stdout · line 1 · 2004-04-28 21:08:35 — "2004-04-28 21:08:35.465325 IP 137.30.123.234.2026 > 137.30.120.37.80: Flags [S], seq 1530203853, win 64240, options [mss 1460,nop,nop,sackOK], length 0"  
  `call_id=86`
- …and 3 further record(s) in the execution trace

*Claim C0011 · Trace calls 23, 86*

<a id="f-007"></a>

### F-007 · HTTP Download of rhino.exe — RHINOUSB [LIKELY]

**What happened.** Source host 137.30.123.234 downloaded rhino.exe (~131 KB, Content-Type: application/octet-stream) from the /~gnome/ web directory on 137.30.120.37:80 at 2004-04-28 21:16:23 UTC. The suspect had previously searched Google for "rhino.exe" at 21:15:48 UTC, approximately 35 seconds before the download. This is recorded in rhino3.log.

**Why it matters.** The download of an executable file (rhino.exe) is a significant escalation from the image downloads in F-006. The 35-second gap between the Google search for "rhino.exe" and the actual download strongly suggests the actor was specifically seeking this file and located it via search. The Content-Type application/octet-stream indicates the server did not identify the file as a specific MIME type, which is typical for executables served from a personal web directory. The file was served from the same /~gnome/ directory, maintaining the connection to the gnome account. The purpose of rhino.exe is not determined by the available evidence; it may be a steganography tool, a file-encryption utility, or another instrument related to the contraband. No uncertainty is noted in the claim itself, though the file's function remains undetermined.

**Evidence.**

- 2004-04-28 21:16:23 — "137.30.123.234 :: 2004-04-28 21:16:23.340464 IP 137.30.123.234.2163 > 137.30.120.37.80: Flags [S], seq"  
  `call_id=87`
- 20260929T165905_551584_18_sudo.stdout · line 6 · 2004-04-28 21:16:23 — "2004-04-28 21:16:23.384261 IP 137.30.120.37.80 > 137.30.123.234.2163: Flags [.], seq 1:1461, ack 394, win 49247, length 1460: HTTP: HTTP/1.1 200 OK"  
  `call_id=87`
- 20260929T165905_551584_18_sudo.stdout · line 12 · 2004-04-28 21:16:23 — "2004-04-28 21:16:23.418282 IP 137.30.120.37.80 > 137.30.123.234.2163: Flags [.], seq 5841:7301, ack 394, win 49247, length 1460: HTTP"  
  `call_id=87`
- …and 3 further record(s) in the execution trace

*Claim C0012 · Trace calls 24, 87*

<a id="f-008"></a>

### F-008 · Steganographic Carrier Images: Extraction Limitation — RHINOUSB [SUSPECTED]

**What happened.** The two carrier images holding JPHide steganographic payloads are among the carved rhino JPGs on the reformatted USB key. The JPHide passwords are derivable from the recovered diary and decoy files (monkey, gator, gumbo). All six unique carved JPGs plus the network-recovered rhino4.jpg were tested with steghide, outguess, and jpseek across all three passwords (24 cells total), but no payload was recovered. The installed JPHide reader (jpseek) covers only the JPHide Linux 0.3 line and cannot read JPHS for Windows 0.5x; the carriers were most likely embedded with JPHide for Windows 0.5x.

**Why it matters.** This finding represents a tooling limitation rather than a negative result. The systematic testing (7 images × 3 passwords × multiple tools = 24 cells) was thorough, and the failure to extract is attributed to a version mismatch: the carriers were embedded with JPHide for Windows 0.5x, while the available extraction tool (jpseek 0.3) only supports the Linux 0.3 format. The password derivation logic is sound — the three candidates (monkey, gator, gumbo) are all directly supported by the recovered evidence (diary text and decoy filenames). The specific filenames of the two carrier images cannot be determined without a JPHS-compatible tool. This is a gap in the current investigation: obtaining or building a JPHS 0.5x-compatible extractor would likely resolve the steganographic payloads. The confidence is SUSPECTED because the version mismatch is inferred from the tool's documented limitations rather than confirmed by direct analysis of the carrier format.

**Evidence.**

- 20260929T165905_551584_17_sudo.stdout · line 1 · 2004-04-28 21:08:35 — "2004-04-28 21:08:35.465325 IP 137.30.123.234.2026 > 137.30.120.37.80: Flags [S], seq 1530203853, win 64240, options [mss 1460,nop,nop,sackOK], length 0"  
  `call_id=86`
- 20260929T165905_551584_17_sudo.stdout · line 6 · 2004-04-28 21:08:35 — "2004-04-28 21:08:35.481949 IP 137.30.120.37.80 > 137.30.123.234.2026: Flags [P.], seq 1:589, ack 384, win 49257, length 588: HTTP: HTTP/1.1 301 Moved Permanently"  
  `call_id=86`
- 20260929T165905_551584_17_sudo.stdout · line 10 · 2004-04-28 21:08:35 — "2004-04-28 21:08:35.819504 IP 137.30.120.37.80 > 137.30.123.234.2026: Flags [P.], seq 589:1568, ack 768, win 48873, length 979: HTTP: HTTP/1.1 200 OK"  
  `call_id=86`
- …and 3 further record(s) in the execution trace

*Claim C0013 · Trace calls 86*

<a id="f-009"></a>

### F-009 · Cross-Evidence Link: gnome Account (Initial) — RHINOUSB [LIKELY]

**What happened.** The gnome account is the connecting thread between USB content and network traffic. The carved diary on the reformatted USB key states "I need to change the password on the gnome account that Jeremy gave me." The same gnome account is used in the network traces: FTP login USER gnome / PASS gnome123 to the "cook" server 137.30.120.40, and HTTP downloads from the /~gnome/ web directory on 137.30.120.37. The rhino images transferred over the network are the same contraband the diary says the suspect possessed and tried to hide.

**Why it matters.** This finding establishes the primary cross-evidence relation in the case. The gnome account appears on both sides of the evidence boundary: it is named in the USB-side diary (a physical artifact recovered from the reformatted key) and it is the credential used in the network-side transfers (captured in pcaps). The logical connection is direct — the same account identifier, the same contraband (rhino images), and the same actor (the suspect who wrote the diary and performed the transfers). This relation is the answer to the case question regarding how the USB content and network traffic are connected. The evidence is consistent and mutually reinforcing: the diary explains the motivation (hiding the rhino images), and the network traces show the actual exfiltration. No uncertainty is noted.

**Evidence.**

- 20260929T165035_551584_8_sudo.stdout · line 6 · 2004-04-26 22:21:43 — "2004-04-26 22:21:43.598613 IP 137.30.122.253.1655 > 137.30.120.40.21: Flags [P.], seq 1:13, ack 29, win 64212, length 12: FTP: USER gnome"  
  `call_id=29`
- 20260929T165035_551584_8_sudo.stdout · line 4 · 2004-04-26 22:21:39 — "2004-04-26 22:21:39.998180 IP 137.30.120.40.21 > 137.30.122.253.1655: Flags [P.], seq 1:29, ack 1, win 49640, length 28: FTP: 220 cook FTP server ready."  
  `call_id=29`
- 20260929T165905_551584_17_sudo.stdout · line 2 · 2004-04-28 21:08:35 — "2004-04-28 21:08:35.466361 IP 137.30.120.37.80 > 137.30.123.234.2026: Flags [S.], seq 1227469043, ack 1530203854, win 49640, options [mss 1460,nop,nop,sackOK], length 0"  
  `call_id=86`
- …and 3 further record(s) in the execution trace

*Claim C0014 · Trace calls 29, 62, 86, 87, 88, 89*

<a id="f-010"></a>

### F-010 · Encrypted ZIP: contraband.zip — RHINOUSB [LIKELY]

**What happened.** The file contraband.zip (230,566 bytes) was uploaded via FTP at 2004-04-26 22:26:46 UTC from 137.30.122.253 to the "cook" FTP server 137.30.120.40:21 using the gnome/gnome123 account. The extracted stream is a valid encrypted ZIP (PK header, flags bit 0 set, deflate compression) containing a single entry named rhino2.jpg. The local file header declares a compressed size of 230,416 bytes while the extracted stream is 1,393 bytes. The ZIP password is derivable from the recovered diary and decoy files: monkey, gator, and gumbo.

**Why it matters.** The encrypted ZIP is the container for rhino2.jpg, the one rhino image not directly uploaded as a standalone file in the FTP session (F-002). The encryption (flags bit 0 set) indicates the suspect took additional steps to protect this particular image, possibly because it was the most incriminating or because it was the last one added to the transfer. The discrepancy between the declared compressed size (230,416 bytes) and the actual extracted stream size (1,393 bytes) is notable and may indicate truncation during extraction or a malformed header; this should be investigated further. The password candidates (monkey, gator, gumbo) are the same as those for the steganographic carriers, suggesting a consistent password scheme across the suspect's anti-forensic measures. The ZIP was uploaded as the last file in the FTP session (22:26:46), after the two standalone images, which is consistent with the diary's narrative of the suspect trying to "not destroy the good stuff." No uncertainty is noted in the claim.

**Evidence.**

- source not identified — "Found file of type "zip" in session [137.30.122.253:53767 -> 137.30.120.40:5120], exporting to /home/analyst/cases/RHINO-HUNT/analysis/contraband_stream2/00000000.zip"  
  `call_id=213`

*Claim C0015 · Trace calls 24, 211, 213, 216, 217, 218*

<a id="f-011"></a>

### F-011 · Cross-Evidence Link: gnome Account (Detailed) — RHINOUSB [LIKELY]

**What happened.** The gnome account is the connecting thread between USB content and network traffic. The carved diary (00335017.ole) on the reformatted USB key states "I need to change the password on the gnome account that Jeremy gave me" — this is the USB-side term. The same gnome account appears in the network traffic: FTP session in rhino.log uses USER gnome / PASS gnome123 to upload rhino1.jpg, rhino3.jpg, and contraband.zip to the "cook" server at 137.30.120.40:21; HTTP sessions in rhino2.log and rhino3.log download rhino4.jpg, rhino5.gif, and rhino.exe from the /~gnome/ web directory on 137.30.120.37:80. The relation proves the USB content and network traffic belong to the same actor.

**Why it matters.** This finding provides the most detailed articulation of the cross-evidence relation, explicitly identifying the USB-side term (gnome account named in the diary) and the network-side terms (137.30.120.40 for FTP, 137.30.120.37 for HTTP). The logical structure is: the diary on the USB key names the account → the same account is used in the network transfers → therefore the USB content and network traffic are attributable to the same actor. This is a direct identity relation, not a probabilistic one. The evidence is internally consistent: the diary's narrative of hiding rhino images aligns with the network transfers of rhino images, and the gnome account is the single identifier that bridges the two evidence domains. No uncertainty is noted.

**Evidence.**

- 20260929T165035_551584_8_sudo.stdout · line 6 · 2004-04-26 22:21:43 — "2004-04-26 22:21:43.598613 IP 137.30.122.253.1655 > 137.30.120.40.21: Flags [P.], seq 1:13, ack 29, win 64212, length 12: FTP: USER gnome"  
  `call_id=29`
- 20260929T165035_551584_8_sudo.stdout · line 7 · 2004-04-26 22:21:43 — "2004-04-26 22:21:43.598813 IP 137.30.120.40.21 > 137.30.122.253.1655: Flags [.], ack 13, win 49640, length 0"  
  `call_id=29`
- 20260929T165905_551584_17_sudo.stdout · line 9 · 2004-04-28 21:08:35 — "2004-04-28 21:08:35.736082 IP 137.30.120.37.80 > 137.30.123.234.2026: Flags [.], ack 768, win 48873, length 0"  
  `call_id=86`
- …and 3 further record(s) in the execution trace

*Claim C0016 · Trace calls 24, 29, 86, 87, 88, 89, 90, 91*

<a id="f-012"></a>

### F-012 · Cross-Evidence Relation: gnome Account (Summary) — RHINOUSB [LIKELY]

**What happened.** The gnome account (USB-side: named in carved diary 00335017.ole on RHINOUSB.dd) is the same account used in FTP uploads to 137.30.120.40 (network-side: rhino.log) and HTTP downloads from 137.30.120.37 (network-side: rhino2.log, rhino3.log).

**Why it matters.** This finding is a concise restatement of the cross-evidence relation established in F-009 and F-011. It identifies the three network-side artifacts (rhino.log, rhino2.log, rhino3.log) and the single USB-side artifact (00335017.ole) that together form the evidence chain. The relation is an identity: the same account name appears in both domains. The forensic significance is that it allows the investigator to attribute all network activity in the three pcaps to the same actor who authored the diary on the USB key, thereby linking the physical evidence to the digital evidence. No uncertainty is noted.

**Evidence.**

- 20260929T165035_551584_8_sudo.stdout · line 1 · 2004-04-26 22:21:39 — "2004-04-26 22:21:39.969811 IP 137.30.122.253.1655 > 137.30.120.40.21: Flags [S], seq 1356543175, win 64240, options [mss 1460,nop,nop,sackOK], length 0"  
  `call_id=29`
- 20260929T165035_551584_8_sudo.stdout · line 35 · 2004-04-26 22:21:59 — "2004-04-26 22:21:59.483409 IP 137.30.122.253.1658 > 137.30.120.40.21: Flags [P.], seq 1:13, ack 29, win 64212, length 12: FTP: USER gnome"  
  `call_id=29`
- 20260929T165905_551584_17_sudo.stdout · line 10 · 2004-04-28 21:08:35 — "2004-04-28 21:08:35.819504 IP 137.30.120.37.80 > 137.30.123.234.2026: Flags [P.], seq 589:1568, ack 768, win 48873, length 979: HTTP: HTTP/1.1 200 OK"  
  `call_id=86`
- …and 3 further record(s) in the execution trace

*Claim C0017 · Trace calls 24, 29, 86, 87, 88, 89, 90, 91*

<a id="f-015"></a>

### F-015 · Steganographic Carrier Images: Tooling Limitation (Detailed) — RHINOUSB [SUSPECTED]

**What happened.** The two carrier images holding JPHide steganographic payloads are among the seven carved rhino JPGs on the reformatted USB key (carved by foremost from RHINOUSB.dd). The JPHide passwords are derivable from the recovered diary and decoy files: monkey (from the diary text), gator (from the alligator decoy context), and gumbo (from the two gumbo-recipe decoy files). The steg_extract tool (jpseek 0.3) was run over the carved JPGs with all three passphrases but returned no extractable payload. The carriers use JPHide 0.5x (Windows) format, which jpseek 0.3 cannot read. The specific filenames of the two carrier images cannot be determined without a JPHS-compatible extraction tool.

**Why it matters.** This finding is a more detailed version of F-008, specifying that the carving was performed by foremost and that seven JPGs were carved (as opposed to the six unique plus one network-recovered image mentioned in F-008). The password derivation is explicitly attributed: monkey from the diary text, gator from the alligator decoy context, and gumbo from the decoy filenames. The tooling limitation is the same: jpseek 0.3 supports only JPHide Linux 0.3, not JPHS for Windows 0.5x. The practical implication is that the steganographic payloads remain unrecovered pending acquisition of a compatible tool. The confidence is SUSPECTED because the attribution of the carriers to JPHS 0.5x is inferred from the tool's documented limitations and the failure to extract, rather than confirmed by direct format analysis of the carrier files. The specific carrier filenames remain undetermined.

**Evidence.**

- gumbo2.txt · line 1 — "Output written to /home/analyst/cases/RHINO-HUNT/analysis/gumbo2.txt"  
  `call_id=28`
- gumbo1.txt · line 1 — "{"success": true, "path": "analysis/gumbo1.txt", "encoding": "cp1252", "size_bytes": 2815, "total_lines": 58, "line_range": [1, 58], "truncated": false, "lines": ["SHRIMP AND TASSO GUMBO", "", "Associate Food Editor: Alexis Touchet", "Fathe …"  
  `call_id=50`
- gumbo2.txt · line 1 — "{"success": true, "path": "analysis/gumbo2.txt", "encoding": "cp1252", "size_bytes": 1293, "total_lines": 38, "line_range": [1, 38], "truncated": false, "lines": ["SHRIMP AND ANDOUILLE SAUSAGE GUMBO", "", "1/2 cup vegetable oil", "1/2 cup a …"  
  `call_id=51`
- …and 1 further record(s) in the execution trace

*Claim C0020 · Trace calls 28, 50, 51, 53, 60, 189, 190*

## 5. Attack Timeline

Curated attack timeline derived from resolved evidence records linked to findings. Supporting claim-relevant detail is also in `master_timeline.tsv` (see Appendix) — that file is curated, not a raw EVTX/session dump.

| Timestamp | Host | User | Event | Finding | Evidence Ref |
|-----------|------|------|-------|---------|--------------|
| 2004-04-26 22:20:23 | RHINOUSB | — | 137.30.122.253 :: 2004-04-26 22:20:23.576821 IP 137.30.122.253.1653 > 137.30.120 | F-001 | supporting_evidence |
| 2004-04-26 22:20:23 | RHINOUSB | — | 2004-04-26 22:20:23.606302 IP 137.30.122.253.1653 > 137.30.120.40.23: Flags [P.] | F-001 | 20260929T165035_551584_9_sudo.stdout · L5 |
| 2004-04-26 22:20:23 | RHINOUSB | — | 2004-04-26 22:20:23.607027 IP 137.30.122.253.1653 > 137.30.120.40.23: Flags [P.] | F-001 | 20260929T165035_551584_9_sudo.stdout · L10 |
| 2004-04-26 22:20:27 | RHINOUSB | — | 2004-04-26 22:20:27.773532 IP 137.30.120.40.23 > 137.30.122.253.1653: Flags [P.] | F-001 | 20260929T165035_551584_9_sudo.stdout · L32 |
| 2004-04-26 22:21:39 | RHINOUSB | — | 2004-04-26 22:21:39.998180 IP 137.30.120.40.21 > 137.30.122.253.1655: Flags [P.] | F-002, F-009 | 20260929T165035_551584_8_sudo.stdout · L4 |
| 2004-04-26 22:21:39 | RHINOUSB | — | 2004-04-26 22:21:39.969811 IP 137.30.122.253.1655 > 137.30.120.40.21: Flags [S], | F-012 | 20260929T165035_551584_8_sudo.stdout · L1 |
| 2004-04-26 22:21:39 | RHINOUSB | — | 2004-04-26 22:21:39.970250 IP 137.30.122.253.1655 > 137.30.120.40.21: Flags [.], | F-017 | 20260929T165035_551584_8_sudo.stdout · L3 |
| 2004-04-26 22:21:43 | RHINOUSB | — | 2004-04-26 22:21:43.598613 IP 137.30.122.253.1655 > 137.30.120.40.21: Flags [P.] | F-002, F-009, F-011, F-017 | 20260929T165035_551584_8_sudo.stdout · L6 |
| 2004-04-26 22:21:43 | RHINOUSB | — | 2004-04-26 22:21:43.598813 IP 137.30.120.40.21 > 137.30.122.253.1655: Flags [.], | F-011 | 20260929T165035_551584_8_sudo.stdout · L7 |
| 2004-04-26 22:21:56 | RHINOUSB | — | 2004-04-26 22:21:56.599918 IP 137.30.122.253.1658 > 137.30.120.40.21: Flags [.], | F-017 | 20260929T165035_551584_8_sudo.stdout · L34 |
| 2004-04-26 22:21:59 | RHINOUSB | — | 2004-04-26 22:21:59.487820 IP 137.30.120.40.21 > 137.30.122.253.1658: Flags [P.] | F-002 | 20260929T165035_551584_8_sudo.stdout · L37 |
| 2004-04-26 22:21:59 | RHINOUSB | — | 2004-04-26 22:21:59.483409 IP 137.30.122.253.1658 > 137.30.120.40.21: Flags [P.] | F-012 | 20260929T165035_551584_8_sudo.stdout · L35 |
| 2004-04-28 21:08:35 | RHINOUSB | — | 2004-04-28 21:08:35.465325 IP 137.30.123.234.2026 > 137.30.120.37.80: Flags [S], | F-006, F-008 | 20260929T165905_551584_17_sudo.stdout · L1 |
| 2004-04-28 21:08:35 | RHINOUSB | — | 2004-04-28 21:08:35.481949 IP 137.30.120.37.80 > 137.30.123.234.2026: Flags [P.] | F-008 | 20260929T165905_551584_17_sudo.stdout · L6 |
| 2004-04-28 21:08:35 | RHINOUSB | — | 2004-04-28 21:08:35.819504 IP 137.30.120.37.80 > 137.30.123.234.2026: Flags [P.] | F-008, F-012 | 20260929T165905_551584_17_sudo.stdout · L10 |
| 2004-04-28 21:08:35 | RHINOUSB | — | 2004-04-28 21:08:35.466361 IP 137.30.120.37.80 > 137.30.123.234.2026: Flags [S.] | F-009 | 20260929T165905_551584_17_sudo.stdout · L2 |
| 2004-04-28 21:08:35 | RHINOUSB | — | 2004-04-28 21:08:35.736082 IP 137.30.120.37.80 > 137.30.123.234.2026: Flags [.], | F-011 | 20260929T165905_551584_17_sudo.stdout · L9 |
| 2004-04-28 21:08:38 | RHINOUSB | — | 2004-04-28 21:08:38.104863 IP 137.30.123.234.2026 > 137.30.120.37.80: Flags [.], | F-006 | 20260929T165905_551584_17_sudo.stdout · L31 |
| 2004-04-28 21:08:38 | RHINOUSB | — | 2004-04-28 21:08:38.111439 IP 137.30.123.234.2026 > 137.30.120.37.80: Flags [.], | F-006 | 20260929T165905_551584_17_sudo.stdout · L37 |
| 2004-04-28 21:08:38 | RHINOUSB | — | 2004-04-28 21:08:38.111213 IP 137.30.120.37.80 > 137.30.123.234.2026: Flags [P.] | F-009 | 20260929T165905_551584_17_sudo.stdout · L36 |
| 2004-04-28 21:16:23 | RHINOUSB | — | 137.30.123.234 :: 2004-04-28 21:16:23.340464 IP 137.30.123.234.2163 > 137.30.120 | F-007 | supporting_evidence |
| 2004-04-28 21:16:23 | RHINOUSB | — | 2004-04-28 21:16:23.384261 IP 137.30.120.37.80 > 137.30.123.234.2163: Flags [.], | F-007 | 20260929T165905_551584_18_sudo.stdout · L6 |
| 2004-04-28 21:16:23 | RHINOUSB | — | 2004-04-28 21:16:23.418282 IP 137.30.120.37.80 > 137.30.123.234.2163: Flags [.], | F-007 | 20260929T165905_551584_18_sudo.stdout · L12 |
| 2004-04-28 21:16:23 | RHINOUSB | — | 2004-04-28 21:16:23.482452 IP 137.30.123.234.2163 > 137.30.120.37.80: Flags [.], | F-007 | 20260929T165905_551584_18_sudo.stdout · L37 |
| 2004-04-28 21:16:23 | RHINOUSB | — | 2004-04-28 21:16:23.415635 IP 137.30.120.37.80 > 137.30.123.234.2163: Flags [.], | F-009 | 20260929T165905_551584_18_sudo.stdout · L9 |
| 2004-04-28 21:16:23 | RHINOUSB | — | 2004-04-28 21:16:23.508246 IP 137.30.123.234.2163 > 137.30.120.37.80: Flags [.], | F-009 | 20260929T165905_551584_18_sudo.stdout · L43 |
| 2004-04-28 21:16:23 | RHINOUSB | — | 2004-04-28 21:16:23.340464 IP 137.30.123.234.2163 > 137.30.120.37.80: Flags [S], | F-011 | 20260929T165905_551584_18_sudo.stdout · L1 |
| 2004-04-28 21:16:23 | RHINOUSB | — | 2004-04-28 21:16:23.483460 IP 137.30.120.37.80 > 137.30.123.234.2163: Flags [.], | F-011, F-012 | 20260929T165905_551584_18_sudo.stdout · L38 |
| 2004-04-28 21:16:23 | RHINOUSB | — | 2004-04-28 21:16:23.341432 IP 137.30.120.37.80 > 137.30.123.234.2163: Flags [S.] | F-012 | 20260929T165905_551584_18_sudo.stdout · L2 |

## 6. Evidence Gaps and Open Questions

### 1. Steganographic Payloads Not Extractable (F-008, F-015)

The two JPHide carrier images among the carved rhino JPGs on RHINOUSB.dd could not be unpacked. The installed extraction tool (jpseek 0.3) covers only the JPHide Linux 0.3 format; the carriers were most likely embedded with JPHide for Windows 0.5x, which the current toolset cannot read (C0013, C0020). As a result:

- The specific filenames of the two carrier images remain undetermined.
- The steganographic payloads (presumably additional rhino images or related content) are not recovered.
- A JPHS-compatible extraction tool (e.g., JPHide for Windows 0.5x or a multi-version reader) is required to close this gap.

### 2. Encrypted ZIP Content Unresolved (F-010)

The file `contraband.zip` uploaded via FTP (C0015) is a valid encrypted ZIP containing a single entry named `rhino2.jpg`. Two issues remain open:

- **Size discrepancy:** The local file header declares a compressed size of 230,416 bytes, but the extracted stream is only 1,393 bytes. This suggests the stream capture may be truncated or incomplete, and the full content of `rhino2.jpg` has not been recovered.
- **Password confirmation:** The candidate passwords (monkey, gator, gumbo) are derivable from the diary and decoy files, but the claim does not state that decryption was successfully completed. The actual content of `rhino2.jpg` remains unverified.

### 3. Hard Drive Unavailable (F-005)

The carved diary (C0010) states the suspect "zapped the hard drive and then threw it into the Mississippi River." No forensic image of the hard drive is available for examination. Any content that resided solely on the hard drive (e.g., the original rhino photos before deletion, additional diary entries, or other artifacts) is unrecoverable from this host.

### 4. Telnet Interactive Payload Pending (F-001)

The telnet session from 137.30.122.253 to 137.30.120.40:23 (C0003) is identified as the channel through which the gnome account was likely granted. The interactive payload is noted as "being extracted to identify who granted the FTP/telnet account." Until that extraction is complete, the identity of the account grantor (referred to as "Jeremy" in the diary) is not independently confirmed from the network trace itself.

### 5. rhino.exe Purpose Undetermined (F-007)

The file `rhino.exe` (~131 KB) was downloaded from the /~gnome/ web directory at 2004-04-28 21:16:23 UTC (C0012). The suspect had searched Google for "rhino.exe" approximately 35 seconds prior. No hash, file-type analysis, or behavioral examination of `rhino.exe` is recorded in the current findings. Its purpose (e.g., stego tool, image viewer, or unrelated) remains open.

### 6. Carving Completeness (F-003)

The USB key was reformatted as a superfloppy, and the original content (rhino images, diary, stego carriers) was recovered from unallocated space via carving (C0008). The findings document 7 carved JPGs and 1 OLE document, but no statement confirms that the carving pass is exhaustive. Additional artifacts (e.g., partial files, other document types, or fragments) may exist in unallocated space and have not been identified.

### 7. Temporal Discrepancy in HTTP Directory Listing (F-006)

The directory listing at /~gnome/ shows `rhino4.jpg` and `rhino5.gif` dated 28-Apr-2004 16:09, while the HTTP download occurred at 21:08:38 UTC (C0011). This ~5-hour offset is likely a timezone difference (server local time vs. UTC), but it is not explicitly resolved in the findings. If the server timezone is not confirmed, the upload timestamp for these files to the web directory cannot be precisely correlated with the FTP upload session in rhino.log.

## 7. Recommendations

*This case is an examination after the fact. The owner's duties remain: each measure below applies to systems still in service, and only if the owner has not already taken it. A measure derived from the ATT&CK mitigation table is a lesson for the owner, not a first-hour step.*

*The brief does not say whose system this is; the recommendations assume the owner is the victim.*

### Do now

- **Assess legal and notification duties for the data believed to be taken** (host, now) — derived from the findings: C0004 [LIKELY]
  - precaution for a suspected exfiltration incident, indicated by C0004

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
- Scope: `host` host=`RHINOUSB`
- Findings rendered: 14

### Conflicts

No open Conflict Findings in Current Investigation State.

<!-- section:exec_summary status:current claims:C0003,C0004,C0008,C0009,C0010,C0011,C0012,C0013,C0014,C0015,C0016,C0017,C0020,C0021 conclusions:N0022 conflicts: -->
<!-- section:scope_evidence status:current claims: conclusions: conflicts: -->
<!-- section:key_findings status:current claims:C0003,C0004,C0008,C0009,C0010,C0011,C0012,C0013,C0014,C0015,C0016,C0017,C0020,C0021 conclusions:N0022 conflicts: -->
<!-- section:detailed_findings status:current claims:C0003,C0004,C0008,C0009,C0010,C0011,C0012,C0013,C0014,C0015,C0016,C0017,C0020,C0021 conclusions:N0022 conflicts: -->
<!-- section:timeline status:current claims:C0003,C0004,C0008,C0009,C0010,C0011,C0012,C0013,C0014,C0015,C0016,C0017,C0020,C0021 conclusions:N0022 conflicts: -->
<!-- section:gaps status:current claims:C0003,C0004,C0008,C0009,C0010,C0011,C0012,C0013,C0014,C0015,C0016,C0017,C0020,C0021,N0022 conclusions:N0022 conflicts: -->
<!-- section:recommendations status:current claims:C0003,C0004,C0008,C0009,C0010,C0011,C0012,C0013,C0014,C0015,C0016,C0017,C0020,C0021 conclusions:N0022 conflicts: -->
<!-- section:appendix status:current claims: conclusions: conflicts: -->
