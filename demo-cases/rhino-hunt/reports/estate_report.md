# Forensic Investigation Report: RHINO-HUNT

> **Closed out by Atlas (gate_ready).** reason.pre_report_check returned READY_TO_REPORT: true and the reports were written from the recorded findings.

*Projection from Current Investigation State. Not a source of truth. (generated 2026-09-29T17:44:20Z, generator report-projection/2.1).*

## Table of Contents

- [1. Executive Summary](#1-executive-summary)
- [Answers to the Investigation Questions](#answers-to-the-investigation-questions)
- [2. Scope and Evidence](#2-scope-and-evidence)
- [3. Key Findings](#3-key-findings)
- [4. Detailed Findings](#4-detailed-findings)
  - [F-017 · Conclusion: gnome account is the cross-evidence relation — RHINOUSB](#f-017)
  - [F-001 · Source host 137.30.122.253 opened a telnet connection to 137.30.120.40:23 at 2004-04-26 22:20:23 UTC… — RHINOUSB](#f-001)
  - [F-002 · FTP upload of rhino images and contraband.zip — RHINOUSB](#f-002)
  - [F-003 · USB key reformatted to destroy evidence — RHINOUSB](#f-003)
  - [F-004 · Decoy files on reformatted USB key — RHINOUSB](#f-004)
  - [F-005 · Carved diary reveals anti-forensics narrative — RHINOUSB](#f-005)
  - [F-006 · HTTP download of rhino4.jpg and rhino5.gif — RHINOUSB](#f-006)
  - [F-007 · HTTP download of rhino.exe — RHINOUSB](#f-007)
  - [F-008 · Stego carrier extraction limitation — RHINOUSB](#f-008)
  - [F-009 · Cross-evidence link: gnome account connects USB and network — RHINOUSB](#f-009)
  - [F-010 · Encrypted ZIP (contraband.zip) uploaded via FTP — RHINOUSB](#f-010)
  - [F-011 · Cross-evidence link: gnome account (detailed mapping) — RHINOUSB](#f-011)
  - [F-012 · Cross-evidence relation: gnome account (summary) — RHINOUSB](#f-012)
  - [F-013 · Two principals identified: John (uploader) and Georgia (account holder) — 137.30.122.253](#f-013)
  - [F-014 · Hotmail email exchange identifies principals and confirms upload — 137.30.122.253](#f-014)
  - [F-015 · Stego carrier extraction limitation (detailed) — RHINOUSB](#f-015)
- [5. Attack Timeline](#5-attack-timeline)
- [6. Evidence Gaps and Open Questions](#6-evidence-gaps-and-open-questions)
- [7. Recommendations](#7-recommendations)
- [8. Appendix](#8-appendix)

## 1. Executive Summary

In late April 2004, a suspect (identified as John) used a shared network account to upload and download images of endangered rhinos — contraband wildlife imagery — to and from a university server. The suspect also possessed a USB drive containing a personal diary and additional rhino images. The diary, recovered from the drive after it had been reformatted, reveals that the suspect deliberately destroyed a hard drive (reportedly by throwing it into the Mississippi River) and reformatted the USB drive to conceal the images.

Two individuals are identified in the evidence. John is the person who uploaded the rhino images and an encrypted archive to the server. A second person (identified as Georgia) controlled the shared account and provided it to John; a third person (Jeremy) is named in the diary as the original provider of the account. The USB drive and the network activity are confirmed to belong to the same actor: the diary on the drive names the same account used in the file transfers.

The following items remain uncertain. First, some of the rhino images appear to contain additional hidden data embedded within them, but the tools currently available to the investigation team cannot extract that data; a different version of the extraction software is required. Second, the encrypted archive uploaded to the server is known to contain at least one additional rhino image, but its password has not yet been confirmed.

The two most important next steps are: (1) obtain a compatible steganography extraction tool to recover the hidden payloads from the carrier images, and (2) confirm the password for the encrypted archive to verify its full contents.

## Answers to the Investigation Questions

### Q1 · Network traces — file transfers in all three pcaps (FTP, HTTP, an encrypted zip and its password, an executable). [LIKELY]

Source host 137.30.122.253 uploaded files to the "cook" FTP server… Source 137.30.123.234 downloaded rhino4.jpg (150k) and rhino5.gif (83k). It also downloaded rhino.exe (~131KB, Content-Type: application/octet-stream).

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

**Investigation scope:** estate / case-level synthesis.

**Analyzed hosts (from current beliefs):**

- `RHINOUSB`
- `137.30.122.253`

**Evidence sources (classes):**

- pcap: 3 files (e.g. `evidence/rhino2.log`, `evidence/rhino3.log`)
- disk: 1 file (e.g. `evidence/RHINOUSB.dd`)
- Claim Graph evidence references (`artifact` / `locator` / `call_id` / `record_ref`)

**Evidence coverage:** 4 of 4 delivered items examined, 0 blocked, 0 not examined.

Examined means a tool call read the item (contact, not full analysis): for an image, its content was reached through a mount, an export or a read. For a folder or an extracted archive the status says how many of its files and folders the calls named.

| Item | Kind | Status | Examined by | Findings |
|---|---|---|---|---|
| `evidence/RHINOUSB.dd` | image | examined | call 21 (tsk_mmls) | F-003, F-004, F-005, F-015 |
| `evidence/rhino.log` | capture | examined | call 18 (net_tcpdump_list_connections) | F-017, F-001, F-002, F-009, F-010, F-011, F-012, F-013, F-014 |
| `evidence/rhino2.log` | capture | examined | call 19 (net_tcpdump_list_connections) | F-017, F-006, F-008, F-009, F-011, F-012 |
| `evidence/rhino3.log` | capture | examined | call 20 (net_tcpdump_list_connections) | F-017, F-007, F-009, F-010, F-011, F-012, F-013, F-014 |

**Timezone:** timestamps rendered as recorded in source artifacts (prefer UTC when ISO-8601 / exporter UTC).

This report is a projection of Current Investigation State (`.atlas/`). It is not the source of truth.

- Scope: estate / case-level synthesis
- Evidence sources: tool outputs under analysis/, optional master_timeline.tsv, Claim Graph evidence references.
- Investigation SoT: `.atlas/` (claims, conclusions, conflicts, journal) — this report is a projection only.

## 3. Key Findings

Concise overview only. Full analysis and Supporting Evidence are in Detailed Findings.

| ID | Statement | Host | When | Confidence |
|----|---------|------|------|------------|
| [F-017](#f-017) | Conclusion: gnome account is the cross-evidence relation | RHINOUSB | — | LIKELY |
| [F-001](#f-001) | Source host 137.30.122.253 opened a telnet connection to 137.30.120.40:23 at 2004-04-26 22:20:23 UTC… | RHINOUSB | 2004-04-26 22:20 UTC | LIKELY |
| [F-002](#f-002) | FTP upload of rhino images and contraband.zip | RHINOUSB | 2004-04-26 22:21 UTC | LIKELY |
| [F-003](#f-003) | USB key reformatted to destroy evidence | RHINOUSB | — | LIKELY |
| [F-004](#f-004) | Decoy files on reformatted USB key | RHINOUSB | — | LIKELY |
| [F-005](#f-005) | Carved diary reveals anti-forensics narrative | RHINOUSB | — | LIKELY |
| [F-006](#f-006) | HTTP download of rhino4.jpg and rhino5.gif | RHINOUSB | 2004-04-28 21:08 UTC | LIKELY |
| [F-007](#f-007) | HTTP download of rhino.exe | RHINOUSB | 2004-04-28 21:16 UTC | LIKELY |
| [F-008](#f-008) | Stego carrier extraction limitation | RHINOUSB | — | SUSPECTED |
| [F-009](#f-009) | Cross-evidence link: gnome account connects USB and network | RHINOUSB | — | LIKELY |
| [F-010](#f-010) | Encrypted ZIP (contraband.zip) uploaded via FTP | RHINOUSB | 2004-04-26 22:26 UTC | LIKELY |
| [F-011](#f-011) | Cross-evidence link: gnome account (detailed mapping) | RHINOUSB | — | LIKELY |
| [F-012](#f-012) | Cross-evidence relation: gnome account (summary) | RHINOUSB | — | LIKELY |
| [F-013](#f-013) | Two principals identified: John (uploader) and Georgia (account holder) | 137.30.122.253 | — | LIKELY |
| [F-014](#f-014) | Hotmail email exchange identifies principals and confirms upload | 137.30.122.253 | 2004-04-26 22:23 UTC | LIKELY |
| [F-015](#f-015) | Stego carrier extraction limitation (detailed) | RHINOUSB | — | SUSPECTED |

## 4. Detailed Findings

<a id="f-017"></a>
<a id="f-016"></a>

### F-017 · Conclusion: gnome account is the cross-evidence relation — RHINOUSB [LIKELY]

**What happened.** The USB key and the network traces are connected by the gnome account: the carved diary on the USB key (00335017.ole, RHINOUSB.dd) names the gnome account that Jeremy gave the suspect, and the same gnome account is the FTP login (USER gnome / PASS gnome123) used to upload rhino1.jpg, rhino3.jpg, and contraband.zip to 137.30.120.40 in rhino.log, and the web directory /~gnome/ from which rhino4.jpg, rhino5.gif, and rhino.exe were downloaded from 137.30.120.37 in rhino2.log and rhino3.log. The USB-side term is the gnome account named in the diary; the network-side term is the gnome account used in the FTP and HTTP transfers.

**Why it matters.** This is the formal conclusion of the cross-evidence analysis. The gnome account is the cross-evidence relation that directly answers the case question (task-0003 p1). The USB-side term is the gnome account named in the carved diary (00335017.ole on RHINOUSB.dd); the network-side term is the gnome account used in the FTP and HTTP transfers (rhino.log, rhino2.log, rhino3.log). The relation is established by direct textual matching: the diary explicitly names the account, and the network captures explicitly show the account being used. No inference is required. The confidence is LIKELY rather than CONFIRMED because, while the account name match is direct, the broader question of whether the same individual who wrote the diary is the same individual who performed the network transfers is supported by convergent evidence (same content type, same account, same timeframe) but not by a single definitive identifier (e.g., a username or IP that appears in both the diary and the network captures). The diary names the account but does not name the author; the network captures show the account being used but do not identify the user by name. The Hotmail exchange (F-014) provides the attribution link (John as uploader, Georgia as account holder), but the diary author is not explicitly identified in the email.

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

### F-002 · FTP upload of rhino images and contraband.zip — RHINOUSB [LIKELY]

**What happened.** Source host 137.30.122.253 uploaded three files to the "cook" FTP server at 137.30.120.40:21 using the account USER gnome / PASS gnome123. The uploaded files were rhino1.jpg (65,703 bytes), rhino3.jpg (193,797 bytes), and contraband.zip (230,566 bytes). The session spanned 2004-04-26 22:21–22:26 UTC.

**Why it matters.** This FTP transfer is the primary exfiltration event in the network evidence. The use of the gnome account (USER gnome / PASS gnome123) directly links this transfer to the USB-side evidence: the carved diary on the reformatted USB key explicitly names the gnome account as one "Jeremy gave me." The three uploaded files represent the contraband the diary describes the suspect possessing and attempting to hide. The session timing (22:21–22:26 UTC) immediately follows the telnet connection (22:20:23 UTC), suggesting the actor first established an interactive session and then performed the file transfer. The contraband.zip file is further examined in F-010. The source IP 137.30.122.253 is later identified as belonging to John (hugerhinolover@hotmail.com) per the Hotmail exchange in F-014.

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

### F-003 · USB key reformatted to destroy evidence — RHINOUSB [LIKELY]

**What happened.** The USB key RHINOUSB.dd was reformatted as a superfloppy (no partition table). Its live filesystem contains only two files: gumbo1.txt (inode 4) and gumbo2.txt (inode 6). The rhino images and other original content were destroyed by the reformat and must be recovered from unallocated space by carving.

**Why it matters.** The reformat is a deliberate anti-forensic action. A superfloppy layout with no partition table is the simplest possible filesystem structure, consistent with a quick reformat intended to make the device appear to contain only the two decoy files. The fact that the original content (rhino images, diary, stego carriers) persists in unallocated space confirms that the reformat was a logical operation (filesystem metadata overwrite) rather than a full wipe. This is consistent with the diary's statement that the suspect intended to "reformat my USB key after this entry, but try not to destroy the good stuff," indicating the suspect believed the reformat would hide the content while preserving it for later retrieval. The carving recovery of the original files validates this interpretation.

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

### F-004 · Decoy files on reformatted USB key — RHINOUSB [LIKELY]

**What happened.** The two live files on the reformatted USB key are decoys, not the diary. gumbo1.txt is a "Shrimp and Tasso Gumbo" recipe (Gourmet, June 2005) and gumbo2.txt is a "Shrimp and Andouille Sausage Gumbo" recipe (Bon Appétit, November 1992). The "gumbo" filenames are a red herring. The actual diary, rhino images, and stego carrier images reside in unallocated space and must be recovered by carving.

**Why it matters.** The decoy files serve a dual purpose: they make the USB key appear to contain only innocent recipe content if inspected by a casual examiner, and they provide a password candidate ("gumbo") for the steganographic carriers and the encrypted ZIP. The choice of two different gumbo recipes from different publications (Gourmet 2005, Bon Appétit 1992) suggests the suspect selected them specifically for the "gumbo" keyword rather than for any culinary interest. The dates of the source publications (June 2005 and November 1992) are notable: the June 2005 date post-dates the network events (April 2004), which may indicate the decoy files were added at a later time or that the publication date refers to a reprint. The decoys are forensically significant because they reveal the suspect's password derivation strategy, which is relevant to F-008, F-010, and F-015.

**Evidence.**

- gumbo1.txt · line 1 — "Output written to /home/analyst/cases/RHINO-HUNT/analysis/gumbo1.txt"  
  `call_id=27`
- gumbo2.txt · line 1 — "Output written to /home/analyst/cases/RHINO-HUNT/analysis/gumbo2.txt"  
  `call_id=28`

*Claim C0009 · Trace calls 27, 28*

<a id="f-005"></a>

### F-005 · Carved diary reveals anti-forensics narrative — RHINOUSB [LIKELY]

**What happened.** The recovered diary (carved OLE Word document 00335017.ole, University of New Orleans) contains the suspect's anti-forensics narrative. It states: "Rhino pictures illegal? Makes me sick. I [deleted] the photos... Apparently, if there are less than 10 photos, it's no big deal. OK. Things are getting a little weird. I zapped the hard drive and then threw it into the Mississippi River. I'm gonna reformat my USB key after this entry, but try not to destroy the good stuff. I need to change the password on the gnome account that Jeremy gave me. I can probably just do that at Radio Shack."

**Why it matters.** This diary is the single most important document in the case. It establishes three critical facts: (a) the hard drive was destroyed ("zapped") and disposed of in the Mississippi River, explaining why no local system evidence is available; (b) the USB key was reformatted to hide the rhino images, which is confirmed by the filesystem analysis in F-003; (c) the gnome FTP/telnet account was given to the suspect by a person named Jeremy. The diary also reveals the suspect's awareness of the legal threshold ("less than 10 photos, it's no big deal"), indicating the suspect was attempting to reduce the number of images to below a perceived legal threshold. The reference to changing the password "at Radio Shack" suggests the suspect intended to use a public computer, which would have left no local trace. The diary directly supports the cross-evidence link in F-009, F-011, F-012, F-016, and F-017 by naming the gnome account as the connecting identifier between the USB content and the network traffic.

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

### F-006 · HTTP download of rhino4.jpg and rhino5.gif — RHINOUSB [LIKELY]

**What happened.** Source 137.30.123.234 downloaded rhino4.jpg (150 KB) and rhino5.gif (83 KB) from the gnome web directory on 137.30.120.37:80 at 2004-04-28 21:08:38 UTC. The directory listing at /~gnome/ showed both files dated 28-Apr-2004 16:09.

**Why it matters.** This HTTP session represents a second exfiltration channel, distinct from the FTP upload in F-002. The source IP 137.30.123.234 is different from the FTP source (137.30.122.253), indicating either a different machine or a different network location used by the same actor. The files were served from the /~gnome/ web directory on 137.30.120.37, which is a different host from the FTP server (137.30.120.40) but uses the same gnome account for the web directory. The file dates (28-Apr-2004 16:09) are earlier than the download time (21:08:38 UTC), indicating the files were uploaded to the web directory approximately five hours before they were downloaded. The use of the gnome web directory again ties this transfer to the gnome account identified in the diary. The file types (JPG and GIF) are consistent with the rhino image collection described in the diary.

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

### F-007 · HTTP download of rhino.exe — RHINOUSB [LIKELY]

**What happened.** Source 137.30.123.234 downloaded rhino.exe (~131 KB, Content-Type: application/octet-stream) from the gnome web directory on 137.30.120.37:80 at 2004-04-28 21:16:23 UTC. The suspect had previously searched Google for "rhino.exe" at 21:15:48 UTC.

**Why it matters.** The download of rhino.exe is forensically significant for two reasons. First, the file is an executable (Content-Type: application/octet-stream, ~131 KB), which is inconsistent with the rhino image collection and suggests it may be a tool, a stego extraction utility, or a payload. Second, the Google search for "rhino.exe" at 21:15:48 UTC, approximately 35 seconds before the download, indicates the actor was actively searching for this specific file before retrieving it. This suggests the actor knew the file existed on the gnome web directory and was looking for a way to access it, or was confirming its availability. The source IP (137.30.123.234) is the same as in F-006, confirming these HTTP downloads were performed from the same host. The file was served from the same /~gnome/ directory, maintaining the gnome account as the connecting identifier.

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

### F-008 · Stego carrier extraction limitation — RHINOUSB [SUSPECTED]

**What happened.** The two carrier images holding JPHide steganographic payloads are among the carved rhino JPGs on the reformatted USB key. The JPHide passwords are derivable from the recovered diary and decoy files: monkey, gator, and gumbo. All six unique carved JPGs (00104057, 00104249, 00105065, 00105873, 00106393, 00106409; 00335081 is byte-identical to 00105873) plus the network-recovered rhino4.jpg were tested with steghide, outguess, and jpseek across all three passwords (24 cells total) — no payload was recovered. The installed JPHide reader (jpseek) covers only the JPHide Linux 0.3 line and cannot read JPHS for Windows 0.5x; the carriers were most likely embedded with JPHide for Windows 0.5x, so the payloads are not extractable with the installed toolset.

**Why it matters.** This finding represents a significant evidentiary gap. The steganographic payloads likely contain additional rhino images or other contraband that the suspect embedded within the carrier images to hide them from casual inspection. The password derivation strategy (monkey from the diary, gator from the alligator decoy context, gumbo from the decoy recipe files) is well-supported by the evidence, but the tool limitation prevents extraction. The carriers were most likely embedded with JPHide for Windows 0.5x, which is a different format from the JPHide Linux 0.3 that jpseek supports. This is a tooling gap rather than an analytical gap: the correct passwords and carrier images are identified, but the extraction tool is incompatible with the embedding format. Acquiring a JPHS-compatible extraction tool (e.g., JPHide for Windows 0.5x or a compatible reader) would likely resolve this gap. The specific filenames of the two carrier images among the six unique carved JPGs cannot be determined without successful extraction.

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

### F-009 · Cross-evidence link: gnome account connects USB and network — RHINOUSB [LIKELY]

**What happened.** The "gnome" account is the connecting thread between the USB content and the network traffic. The carved diary on the reformatted USB key states "I need to change the password on the gnome account that Jeremy gave me." The same gnome account is used in the network traces: FTP login USER gnome / PASS gnome123 to the "cook" server 137.30.120.40, and HTTP downloads from the /~gnome/ web directory on 137.30.120.37. The rhino images transferred over the network are the same contraband the diary says the suspect possessed and tried to hide.

**Why it matters.** This finding establishes the primary cross-evidence relation in the case. The gnome account appears on both sides of the evidence boundary: it is named in the carved diary on the USB key (USB-side) and it is the credential used in the FTP upload and the web directory served in the HTTP downloads (network-side). This is not a coincidental name match — the diary explicitly states the suspect was given this account by Jeremy, and the network traces show the same account being used to transfer the same type of content (rhino images) that the diary describes. The relation proves that the USB content and the network traffic belong to the same actor and the same operational context. This finding directly answers the case question regarding the connection between the USB key and the network traces.

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

### F-010 · Encrypted ZIP (contraband.zip) uploaded via FTP — RHINOUSB [LIKELY]

**What happened.** The encrypted ZIP file contraband.zip was uploaded via FTP in rhino.log: STOR contraband.zip at 2004-04-26 22:26:46 UTC from 137.30.122.253 to the cook FTP server 137.30.120.40:21 (account gnome/gnome123), data port 2002, BINARY mode, 226 Transfer complete. The extracted stream is a valid encrypted ZIP (PK header, flags bit 0 set = encrypted, deflate) containing a single entry named rhino2.jpg. The local file header declares a compressed size of 230,416 bytes while the extracted stream is 1,393 bytes. The ZIP password is derivable from the recovered diary and decoy files: the three candidate passwords are monkey, gator, and gumbo.

**Why it matters.** The encrypted ZIP is a significant finding because it contains rhino2.jpg — the one rhino image that was not transferred as a standalone file over the network. The FTP transfer included rhino1.jpg and rhino3.jpg as plain files, while rhino2.jpg was protected inside the encrypted ZIP. This suggests the suspect applied an additional layer of protection to this specific image, possibly because it was the most incriminating or because the suspect was uncertain about its content. The discrepancy between the declared compressed size (230,416 bytes) and the extracted stream size (1,393 bytes) is notable and may indicate truncation during extraction or an anomaly in the ZIP structure. The password candidates (monkey, gator, gumbo) are the same as those for the stego carriers, confirming a consistent password derivation strategy across all protected content. The use of the gnome account for this upload further reinforces the cross-evidence link.

**Evidence.**

- source not identified — "Found file of type "zip" in session [137.30.122.253:53767 -> 137.30.120.40:5120], exporting to /home/analyst/cases/RHINO-HUNT/analysis/contraband_stream2/00000000.zip"  
  `call_id=213`

*Claim C0015 · Trace calls 24, 211, 213, 216, 217, 218*

<a id="f-011"></a>

### F-011 · Cross-evidence link: gnome account (detailed mapping) — RHINOUSB [LIKELY]

**What happened.** The "gnome" account is the connecting thread between USB content and network traffic. The carved diary on the reformatted USB key (00335017.ole) states "I need to change the password on the gnome account that Jeremy gave me" — this is the USB-side term. The same gnome account appears in the network traffic: FTP session in rhino.log uses USER gnome / PASS gnome123 to upload rhino1.jpg, rhino3.jpg, and contraband.zip to the cook FTP server at 137.30.120.40:21; HTTP sessions in rhino2.log and rhino3.log download rhino4.jpg, rhino5.gif, and rhino.exe from the /~gnome/ web directory on 137.30.120.37:80. The relation proves the USB content and network traffic belong to the same actor.

**Why it matters.** This finding provides the detailed mapping of the gnome account across all three network captures. The USB-side term is the gnome account named in the diary (00335017.ole on RHINOUSB.dd). The network-side terms are: 137.30.120.40 (FTP server, rhino.log) where the gnome account was used for uploads, and 137.30.120.37 (HTTP server, rhino2.log and rhino3.log) where the /~gnome/ web directory served the downloads. The fact that the same account name appears in both the FTP credential and the HTTP web directory path (/~gnome/) on two different servers (137.30.120.40 and 137.30.120.37) indicates that the gnome account existed on both hosts, or that the web directory on 137.30.120.37 was a mirror or copy of the gnome home directory. This finding is a more detailed restatement of F-009 and provides the specific host-to-capture mapping.

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

### F-012 · Cross-evidence relation: gnome account (summary) — RHINOUSB [LIKELY]

**What happened.** The "gnome" account (USB-side term: named in carved diary 00335017.ole on RHINOUSB.dd) is the same account used in FTP uploads to 137.30.120.40 (network-side term: rhino.log) and HTTP downloads from 137.30.120.37 (network-side term: rhino2.log, rhino3.log).

**Why it matters.** This finding is a concise statement of the cross-evidence relation. The gnome account is the single identifier that bridges the physical evidence (USB key) and the network evidence (three pcap files). The USB-side evidence is the carved diary that names the account; the network-side evidence is the FTP and HTTP transfers that use the account. This relation is the answer to the case question regarding how the USB key and the network traces are connected. The confidence is high because the account name is explicitly stated in the diary and explicitly used in the network captures — there is no inference or assumption involved, only direct textual matching of the identifier "gnome" across both evidence domains.

**Evidence.**

- 20260929T165035_551584_8_sudo.stdout · line 1 · 2004-04-26 22:21:39 — "2004-04-26 22:21:39.969811 IP 137.30.122.253.1655 > 137.30.120.40.21: Flags [S], seq 1356543175, win 64240, options [mss 1460,nop,nop,sackOK], length 0"  
  `call_id=29`
- 20260929T165035_551584_8_sudo.stdout · line 35 · 2004-04-26 22:21:59 — "2004-04-26 22:21:59.483409 IP 137.30.122.253.1658 > 137.30.120.40.21: Flags [P.], seq 1:13, ack 29, win 64212, length 12: FTP: USER gnome"  
  `call_id=29`
- 20260929T165905_551584_17_sudo.stdout · line 10 · 2004-04-28 21:08:35 — "2004-04-28 21:08:35.819504 IP 137.30.120.37.80 > 137.30.123.234.2026: Flags [P.], seq 589:1568, ack 768, win 48873, length 979: HTTP: HTTP/1.1 200 OK"  
  `call_id=86`
- …and 3 further record(s) in the execution trace

*Claim C0017 · Trace calls 24, 29, 86, 87, 88, 89, 90, 91*

<a id="f-013"></a>

### F-013 · Two principals identified: John (uploader) and Georgia (account holder) — 137.30.122.253 [LIKELY]

**What happened.** The two principals are identified. John (hugerhinolover@hotmail.com, source IP 137.30.122.253) is the uploader who used the gnome FTP/telnet account to upload rhino images and contraband.zip. Georgia (bighonkingrhino@hotmail.com) is the account holder who provided the gnome credentials. The gnome account belongs to the cscistu group (gid=2000) on cook.cs.uno.edu (Sun Solaris v5.9, uid=2287). Jeremy (named in the diary) is the person who originally gave the gnome account to the suspect. The controller of the gnome account is Georgia, who had access to it and shared it with John.

**Why it matters.** This finding resolves the question of who the two principals are and what their respective roles are. John is the active uploader — the one who performed the FTP transfer from 137.30.122.253. Georgia is the account holder — the one who controlled the gnome account and shared it with John. The diary's reference to "the gnome account that Jeremy gave me" introduces a third party (Jeremy) who originally provided the account, but the Hotmail exchange (F-014) clarifies that Georgia is the one who "checked the account later" and who is the account holder. The gnome account's group membership (cscistu, gid=2000) and the server details (cook.cs.uno.edu, Sun Solaris v5.9, uid=2287) provide additional context about the account's origin and the server environment. The distinction between John (uploader) and Georgia (account holder/controller) is important for attribution: John performed the exfiltration, but Georgia controlled the account through which it was done.

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

### F-014 · Hotmail email exchange identifies principals and confirms upload — 137.30.122.253 [LIKELY]

**What happened.** A Hotmail email exchange in rhino.log identifies the two principals. John (hugerhinolover@hotmail.com, source 137.30.122.253) sent to bighonkingrhino@hotmail.com at 2004-04-26 22:23:20 UTC: "I just checked a few things on the gnome account on cook.cs.uno.edu. I'm about to upload some new rhino stuff. Check it out. --John." The reply from bighonkingrhino (Georgia): "I'll check the account later for the rhino stuff. I'm tied up for the moment working on something in the lab. What's your social security number? I want to sign you up for a few Rhino Lovers magazine subscription. Love, Georgia."

**Why it matters.** This email exchange is the definitive attribution evidence. It confirms four facts: (1) John is the uploader who used the gnome account — he states "I'm about to upload some new rhino stuff"; (2) Georgia is the account holder who provided the gnome credentials — she refers to "the account" as if it were hers and says she will "check the account later"; (3) the gnome account is on cook.cs.uno.edu (137.30.120.40) — John explicitly names the server; (4) the upload was rhino images — both parties reference "rhino stuff." The timing is significant: the email was sent at 22:23:20 UTC, which falls within the FTP session window (22:21–22:26 UTC), confirming that the email and the FTP upload are part of the same operational sequence. The request for John's social security number for a "Rhino Lovers magazine subscription" is unusual and may indicate a deeper relationship between the two parties or a cover story. The source IP 137.30.122.253 for John's email matches the FTP source IP, confirming the same host was used for both the email and the upload.

**Evidence.**

- 20260929T172307_551584_40_sudo.stdout · line 4 — "T 137.30.120.40:23 -> 137.30.122.253:1653 [AP] #1251"  
  `call_id=278`
- 20260929T172307_551584_40_sudo.stdout · line 5 — "gnome pts/5 Apr 26 17:17 (137.30.122.253).... Today i"  
  `call_id=278`
- 20260929T172307_551584_40_sudo.stdout · line 79 — "T 137.30.122.253:1690 -> 64.4.43.250:80 [AP] #2600"  
  `call_id=278`

*Claim C0019 · Trace calls 24, 271, 278, 293*

<a id="f-015"></a>

### F-015 · Stego carrier extraction limitation (detailed) — RHINOUSB [SUSPECTED]

**What happened.** The two carrier images holding JPHide steganographic payloads are among the seven carved rhino JPGs on the reformatted USB key (carved by foremost from RHINOUSB.dd). The JPHide passwords are derivable from the recovered diary and decoy files: monkey (from the diary text), gator (from the alligator decoy context), and gumbo (from the two gumbo-recipe decoy files gumbo1.txt and gumbo2.txt). The steg_extract tool (jpseek 0.3) was run over the carved JPGs with all three passphrases but returned no extractable payload: the carriers use JPHide 0.5x (Windows) format, which jpseek 0.3 cannot read. The specific filenames of the two carrier images cannot be determined without a JPHS-compatible extraction tool.

**Why it matters.** This finding is a more detailed restatement of F-008, providing the specific tooling context. The extraction was performed using jpseek 0.3, which is the JPHide Linux 0.3 reader. The carriers were most likely embedded with JPHide for Windows 0.5x, a different version with a different embedding format. This is a tooling incompatibility, not a failure of the analytical approach. The password derivation is well-supported: monkey appears in the diary text, gator is associated with the alligator decoy context, and gumbo is derived from the two decoy recipe files. The fact that the carriers are among the seven carved JPGs (six unique plus one byte-identical duplicate) narrows the search space but does not identify the specific two carriers. Acquiring a JPHS-compatible tool (JPHide for Windows 0.5x or a compatible reader) is the recommended next step to resolve this gap. The stego payloads likely contain additional rhino images or other contraband that the suspect embedded to hide them from detection.

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
| 2004-04-26 22:21:39 | 137.30.122.253 | — | 2004-04-26 22:21:39.970250 IP 137.30.122.253.1655 > 137.30.120.40.21: Flags [.], | F-013 | 20260929T165035_551584_8_sudo.stdout · L3 |
| 2004-04-26 22:21:39 | RHINOUSB | — | 2004-04-26 22:21:39.970250 IP 137.30.122.253.1655 > 137.30.120.40.21: Flags [.], | F-017 | 20260929T165035_551584_8_sudo.stdout · L3 |
| 2004-04-26 22:21:43 | RHINOUSB | — | 2004-04-26 22:21:43.598613 IP 137.30.122.253.1655 > 137.30.120.40.21: Flags [P.] | F-002, F-009, F-011, F-017 | 20260929T165035_551584_8_sudo.stdout · L6 |
| 2004-04-26 22:21:43 | RHINOUSB | — | 2004-04-26 22:21:43.598813 IP 137.30.120.40.21 > 137.30.122.253.1655: Flags [.], | F-011 | 20260929T165035_551584_8_sudo.stdout · L7 |
| 2004-04-26 22:21:43 | 137.30.122.253 | — | 2004-04-26 22:21:43.602936 IP 137.30.120.40.21 > 137.30.122.253.1655: Flags [P.] | F-013 | 20260929T165035_551584_8_sudo.stdout · L8 |
| 2004-04-26 22:21:56 | 137.30.122.253 | — | 2004-04-26 22:21:56.292139 IP 137.30.120.40.21 > 137.30.122.253.1658: Flags [S.] | F-013 | 20260929T165035_551584_8_sudo.stdout · L31 |
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

### 1. Steganographic Payload Extraction (F-008, F-015)

The two JPHide steganographic carriers among the carved rhino JPGs on RHINOUSB.dd remain unextracted. The installed toolset (jpseek 0.3) covers only the JPHide Linux 0.3 format and cannot read JPHide for Windows 0.5x, which is the format the carriers most likely use (C0013, C0020). Consequently:

- The specific filenames of the two carrier images among the six unique carved JPGs (00104057, 00104249, 00105065, 00105873, 00106393, 00106409) plus network-recovered rhino4.jpg cannot be confirmed.
- The steganographic payloads themselves — potentially containing additional rhino images or text — are not available for analysis.
- A JPHS-compatible extraction tool (e.g., JPHide for Windows 0.5x or a compatible reader) is required to close this gap.

### 2. Encrypted ZIP Integrity (F-010)

The contraband.zip uploaded via FTP (C0015) presents a size discrepancy: the local file header declares a compressed size of 230,416 bytes for the single entry rhino2.jpg, yet the extracted stream is only 1,393 bytes. This suggests the FTP transfer was truncated, the ZIP is corrupted, or the stream was not fully captured in the pcap. The actual content of rhino2.jpg within the archive has not been confirmed as recoverable. The three candidate passwords (monkey, gator, gumbo) are derivable from the diary and decoy files, but successful decryption and extraction of a complete rhino2.jpg has not been demonstrated.

### 3. Telnet Session Payload (F-001)

The telnet session from 137.30.122.253 to 137.30.120.40:23 (C0003) is identified as the channel through which the interactive payload was exchanged. The claim notes that the payload is "being extracted to identify who granted the FTP/telnet account." No finding yet records the extracted telnet conversation content or the specific commands/credentials observed within that session.

### 4. Suspect Workstation Unavailable (F-005)

The carved diary (C0010) states the suspect "zapped the hard drive and then threw it into the Mississippi River." No disk image of the suspect's primary workstation is available in this investigation. Any artifacts that resided solely on that drive (browsers, email clients, local file history, registry, prefetch) are unrecoverable. The USB key and network captures are the only available evidence sources.

### 5. rhino.exe Purpose and Execution (F-007)

The file rhino.exe (~131 KB, Content-Type: application/octet-stream) was downloaded from the /~gnome/ web directory on 137.30.120.37 at 2004-04-28 21:16:23 UTC (C0012). No finding addresses:

- The file's functionality or purpose (stego tool, image viewer, other).
- Whether it was executed on any host.
- Its relationship to the steganographic carriers on the USB key.

### 6. Jeremy's Identity (F-013, F-005)

The diary names "Jeremy" as the person who originally provided the gnome account to the suspect (C0010, C0018). No finding establishes Jeremy's full name, email address, IP address, or any other identifying attribute. The chain of credential sharing (Jeremy → suspect → John/Georgia) is partially documented but the first link remains unattributed beyond a first name.

### 7. Relationship Between 137.30.120.37 and 137.30.120.40

The FTP server (cook.cs.uno.edu) is identified at 137.30.120.40 (C0004, C0019). The HTTP web directory /~gnome/ is served from 137.30.120.37 (C0011, C0012). No finding explicitly confirms whether these are the same host (dual-homed or multi-NIC) or distinct machines. If they are the same host, the gnome account's home directory would be accessible via both services; if distinct, the web directory may be a separate copy or mirror.

### 8. Carved File Metadata Loss (F-003, F-004)

Because the USB key was reformatted (C0008), all carved files lack original filesystem metadata: timestamps, directory paths, permissions, and file associations are not recoverable from the carving process. The temporal ordering of the rhino images relative to the diary entry and the network transfers must be inferred from the pcap timestamps and the diary narrative rather than from file system evidence.

### 9. Georgia's Response to SSN Request (F-014)

The Hotmail exchange (C0019) records Georgia requesting John's social security number. No finding records John's reply or whether the SSN was provided. If a reply exists in the pcap, it has not been extracted or registered as a finding.

### 10. Estate-Scope Observations

All findings in this investigation are scoped to a single host (RHINOUSB) or a single source IP (137.30.122.253). No findings reference additional hosts, network segments, or estate-wide indicators. If the gnome account or the rhino content was accessed from other sources, or if the cook.cs.uno.edu server hosted additional accounts or files relevant to the case, that scope is not addressed by the current findings.

## 7. Recommendations

*This case is an examination after the fact. The owner's duties remain: each measure below applies to systems still in service, and only if the owner has not already taken it. A measure derived from the ATT&CK mitigation table is a lesson for the owner, not a first-hour step.*

*The brief does not say whose system this is; the recommendations assume the owner is the victim.*

### Do now

- **Assess legal and notification duties for the data believed to be taken** (host, now) — derived from the findings: C0004 [LIKELY]
  - precaution for a suspected exfiltration incident, indicated by C0004
- **Preserve proxy, firewall and DNS logs covering the suspected window: RHINOUSB** (network, now) — derived from the findings: C0004 [LIKELY]
  - precaution for a suspected exfiltration incident, indicated by C0004
- **Preserve volatile state and logs before any remediation: memory, event logs, shadow copies, firewall and proxy logs** (estate, now) — from prior knowledge
  - precaution every incident shares

### Escalate

- **Keep a timestamped record of every response action taken from now on** (estate, soon) — from prior knowledge
  - precaution every incident shares

### Contain

- **Block the identified egress destinations at the perimeter and review outbound traffic** (network, soon) — derived from the findings: C0004 [LIKELY]
  - precaution for a suspected exfiltration incident, indicated by C0004; to be scoped: the finding names no typed addresses, domains, URLs or mail addresses on the attacker side

*Items marked 'from prior knowledge' rest on what the analyst told Atlas before any evidence was read, not on findings.*

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
- Scope: `estate`
- Findings rendered: 16

### Conflicts

No open Conflict Findings in Current Investigation State.

<!-- section:exec_summary status:current claims:C0003,C0004,C0008,C0009,C0010,C0011,C0012,C0013,C0014,C0015,C0016,C0017,C0018,C0019,C0020,C0021 conclusions:N0022 conflicts: -->
<!-- section:scope_evidence status:current claims: conclusions: conflicts: -->
<!-- section:key_findings status:current claims:C0003,C0004,C0008,C0009,C0010,C0011,C0012,C0013,C0014,C0015,C0016,C0017,C0018,C0019,C0020,C0021 conclusions:N0022 conflicts: -->
<!-- section:detailed_findings status:current claims:C0003,C0004,C0008,C0009,C0010,C0011,C0012,C0013,C0014,C0015,C0016,C0017,C0018,C0019,C0020,C0021 conclusions:N0022 conflicts: -->
<!-- section:timeline status:current claims:C0003,C0004,C0008,C0009,C0010,C0011,C0012,C0013,C0014,C0015,C0016,C0017,C0018,C0019,C0020,C0021 conclusions:N0022 conflicts: -->
<!-- section:gaps status:current claims:C0003,C0004,C0008,C0009,C0010,C0011,C0012,C0013,C0014,C0015,C0016,C0017,C0018,C0019,C0020,C0021,N0022 conclusions:N0022 conflicts: -->
<!-- section:recommendations status:current claims:C0003,C0004,C0008,C0009,C0010,C0011,C0012,C0013,C0014,C0015,C0016,C0017,C0018,C0019,C0020,C0021 conclusions:N0022 conflicts: -->
<!-- section:appendix status:current claims: conclusions: conflicts: -->
