"""Gate: a CONFIRMED/LIKELY finding asserting data *left the host* via a named
channel must cite a *transfer* artifact — not tool-execution or file-presence.

Root-cause failure this closes (generic, not scenario-specific): an
investigation promotes an exfiltration channel into the verdict on the strength
of a tool being installed or a file sitting in a sync/staging folder ("Dropbox
client present + archive in the Dropbox folder ⇒ cloud exfil"), while the actual
transfer is never evidenced and a competing channel with stronger evidence is
downranked. "The tool was here" and "the file was in the folder" are *presence*,
not *egress*. A channel claim must rest on a record that bytes actually moved.

Trigger (description prose):
  tier ∈ {CONFIRMED, LIKELY}
  AND the description asserts egress (exfiltrated / uploaded / transferred /
      sent to / copied to / transmitted / leaked)
  AND it names a channel (cloud / Dropbox / OneDrive / GDrive / FTP / USB /
      removable / email / attachment / web upload / C2 / Telegram / SMTP).

Pass condition (evidence, NOT prose): a transfer marker appears in
lineage_evidence_text(ctx) — the agent's supporting_evidence plus the cmd /
stdout_excerpt of the linked_call_id and input_call_ids entries. Transfer
markers: an FTP/transfer log (transfers.log), a byte-count of data sent/written/
transferred, a USN $J write/rename record, a removable-volume LNK / MountedDevices
/ DEVPKEY binding (the file physically resided on removable media), a mail record
carrying an attachment, netflow/pcap egress, SRUM per-app network bytes, or the
protocol exchange of a transfer captured on the wire (an FTP STOR/RETR with its
150/226 replies, an HTTP POST/PUT with a body, an SMTP 354/queued reply).

Explicitly NON-satisfying (presence only): a file in a sync/staging folder, a
cloud-client ADS such as :com.dropbox.attributes, or tool-execution alone
("VeraCrypt ran", "Dropbox.exe present"). These describe staging, not egress.
"""
import re
from typing import Optional

from ._match import asserted_mention, lineage_evidence_text

# Asserts data left the host.
_EGRESS_RE = re.compile(
    r"\b(?:exfil\w*|uploaded|upload\b|transferred|transmit\w*|sent to\b"
    r"|copied to\b|leaked|egress\w*)\b",
    re.IGNORECASE,
)

# Names a channel the egress used. Prefer generic channel classes; vendor
# client names still match when the finding names them (claim-driven).
_CHANNEL_RE = re.compile(
    r"\b(?:cloud\b|sync\s*client|file\s*sync|ftp\b|sftp\b|tftp\b"
    r"|usb\b|removable\b|thumb ?drive|flash drive|memory stick|sd card"
    r"|external (?:hard )?(?:disk|drive)|cd-?rw?\b|dvd\b|optical|physical media"
    r"|e-?mail\b|webmail|attachment|web upload|http upload|c2\b|smtp"
    r"|dropbox|onedrive|gdrive|google drive|mega\b|box\.com|telegram)\b",
    re.IGNORECASE,
)

# Evidence that bytes actually moved (a transfer record), as opposed to mere
# staging/presence. A removable-volume binding counts: it is positive evidence
# the file resided on media that physically left the host. So does the
# transfer exchange of a protocol seen in a capture: the command that moves
# a file and the reply that opens or closes its data connection are the
# transfer, whatever the capture file is called (protocol constants, RFC
# 959 / 7231 / 5321 - not knowledge about any case).
_TRANSFER_RE = re.compile(
    r"(?:\btransfers?\.log\b|\bftp log\b"
    r"|\b\d[\d,]*\s*bytes?\s*(?:sent|written|read|transferred|uploaded)\b"
    r"|\bbytes[_ ](?:sent|written|read)\b"
    r"|\busn\b|\$j\b|\$usnjrnl|\busnjrnl\b"
    r"|\b(?:data ?extend|filecreate|file ?write|rename)\b"
    r"|\bmounteddevices\b|\bdevpkey\b|\bremovable\b|\bdisk ?\[usbstor\]"
    r"|\battachment\b|\battached file\b|\bcontent-disposition\b"
    r"|\bnetflow\b|\bpcap\b|\bpackets?\b|\bsrum\b|\bsrudb\b|\bbytessent\b"
    # FTP: a store/retrieve/append command, or the data-connection replies.
    r"|\b(?:STOR|STOU|APPE|RETR)\s+\S"
    r"|\b(?:125|150)\s+(?:Data|Opening|Accepted|File status)\b"
    r"|\b226\s+(?:Transfer|Closing|File)\b"
    # HTTP: an upload request line, or a body of non-zero length.
    r"|\b(?:POST|PUT)\s+/\S*\s+HTTP/\d|\bContent-Length:\s*[1-9]"
    # SMTP: the server accepting a message body, or queuing it.
    r"|\b354\s+(?:Start|End|Enter|Go ahead)\b|\b250\s+2\.0\.0\b|\bqueued as\b)",
    re.IGNORECASE,
)


def asserts_egress(desc: str) -> bool:
    """Whether the description claims data left the host, as opposed to
    only denying that it did: at least one egress verb stands in a sentence
    with no negation before it."""
    return asserted_mention(desc or "", _EGRESS_RE) is not None


# A medium that physically leaves with the data: the data's presence on the
# medium's own file system is the transfer record, whatever the listing
# tool printed. A folder on the host is staging; a file on the stick left.
_PHYSICAL_MEDIA_RE = re.compile(
    r"\b(?:usb\b|removable\b|thumb ?drive|flash drive|memory stick|sd card"
    r"|external (?:hard )?(?:disk|drive)|cd-?rw?\b|dvd\b|optical|physical media)",
    re.IGNORECASE)
# A call that listed or read a file system or an image, by its command.
_FS_READ_RE = re.compile(
    r"\b(?:fls|icat|istat|ffind|ifind|tsk_recover|mmls|fsstat|ls|find|strings)\b"
    r"|/ewf\d*/ewf1\b|/fs/|\.(?:e01|ex01|dd|raw|img|iso|001)\b", re.IGNORECASE)


def _cited_entries(ctx) -> list[dict]:
    cids = list(ctx.input_call_ids or [])
    if ctx.linked_call_id:
        cids.append(ctx.linked_call_id)
    by_id = getattr(ctx.idx, "by_call_id", {}) or {}
    return [by_id[c] for c in cids if isinstance(by_id.get(c), dict)]


def medium_listing_cited(ctx) -> bool:
    """A cited call read the medium's own file system and its output names
    an artifact the finding names: the data is on the medium that left."""
    if not _PHYSICAL_MEDIA_RE.search(ctx.description or ""):
        return False
    try:
        from core.entities import artifact_tokens
    except Exception:  # noqa: BLE001
        return False
    want = artifact_tokens(ctx.description or "")
    if not want:
        return False
    for entry in _cited_entries(ctx):
        cmd = str(entry.get("cmd") or "")
        if not _FS_READ_RE.search(cmd):
            continue
        shown = str(entry.get("stdout_excerpt") or "")
        try:
            from .lineage_relevance import entry_text
            shown = entry_text(entry, include_file=True) or shown
        except Exception:  # noqa: BLE001
            pass
        if artifact_tokens(shown) & want:
            return True
    return False


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None

    desc = ctx.description or ""
    if not (_CHANNEL_RE.search(desc) and asserts_egress(desc)):
        return None

    evidence = lineage_evidence_text(ctx)
    if _TRANSFER_RE.search(evidence) or medium_listing_cited(ctx):
        return None

    return {
        "success": False,
        "error": (
            f"{ctx.tier} finding claims data was exfiltrated over a named channel "
            f"but its evidence (supporting_evidence or the linked_call_id / "
            f"input_call_ids entries) shows only presence/staging, not a transfer. "
            f"A file in a sync folder, a :com.dropbox.attributes ADS, or "
            f"tool-execution alone is not egress. Cite a transfer artifact — an "
            f"FTP/transfer log, a byte count sent/written, a USN $J write/rename, "
            f"a removable-volume LNK / MountedDevices binding, a mail attachment "
            f"record, SRUM/netflow egress, or for a removable or optical medium the "
            f"listing of the medium's own file system naming the data — and link it "
            f"(input_call_ids), or "
            f"downgrade this finding to SUSPECTED. Enumerate ALL candidate channels "
            f"and headline only the strongest-evidenced one."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "exfil_channel_grounding",
    }
