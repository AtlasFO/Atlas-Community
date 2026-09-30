# Case: RHINO-HUNT

**Evidence integrity: Never modify evidence files. All output to `./analysis/`, `./exports/`, or `./reports/`.**

---

## Case Metadata

| Field | Value |
|-------|-------|
| **Case ID** | RHINO-HUNT |
| **Engagement** | examination — the devices and images are examined after the fact; no first-hour response step applies |
| **Scenario** | DFRWS 2005 Rodeo Challenge: possession of nine or more unique rhinoceros images is a crime; a university lab machine was seized **without its hard drive** |
| **Dataset** | NIST CFReDS archive (public) — [scenario](https://cfreds-archive.nist.gov/dfrws/Rhino_Hunt.html), [official answers](https://cfreds-archive.nist.gov/dfrws/DFRWS2005-answers.pdf) |
| **Evidence** | `RHINOUSB.dd` (USB key image) plus three network traces `rhino.log`, `rhino2.log`, `rhino3.log` — **not committed**, fetch from the archive page (MD5s published there) |
| **Your role** | Examiner recovering the rhino images and reconstructing what happened to the missing hard drive |

---

## CASE_QUESTION: Recover the rhino images from the USB key and the network traces, establish who gave the suspect the FTP/telnet account and its credentials, and determine what happened to the missing hard drive and the USB key.

## Investigation Requests

1. **Network traces** — file transfers in all three pcaps (FTP, HTTP, an encrypted zip and its password, an executable).
2. **USB key** — the key was reformatted: recover content by carving; two carrier images hold steganographic payloads (jphide) whose passwords are derivable from the recovered diary.
3. **Cross-evidence link** — prove the connection between USB content and network traffic.
4. **The anti-forensics story** — what the diary says happened to the hard drive and the USB key.
