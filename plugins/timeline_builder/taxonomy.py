"""Evidence-class taxonomy for timeline curation (case-independent).

Maps normalized timeline ``event_type`` / source hints onto forensic
*evidence classes* (execution, authentication, usb, …) and *producers*
(prefetch, security_4688, sysmon_1, …). Used to:

  * infer which classes the case narrative asserts
  * keep multi-perspective corroboration (Prefetch + 4688 + Sysmon)
  * avoid hardcoding allow/deny lists of event_type names from one case

This is a capability map — not an always-keep list. An event is kept when
the narrative needs its class (or it matches focus entities), not because
its type name is on a static allowlist.
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Iterable


class EvidenceClass(str, Enum):
    EXECUTION = "execution"
    FILE_PRESENCE = "file_presence"
    FILE_MODIFICATION = "file_modification"
    FILE_DELETION = "file_deletion"
    PERSISTENCE = "persistence"
    USER_INTERACTION = "user_interaction"
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    USB_DEVICE = "usb_device"
    COMMAND_EXECUTION = "command_execution"
    MALWARE_EXECUTION = "malware_execution"
    LATERAL_REMOTE = "lateral_remote"
    POLICY = "policy"
    FINDING = "finding"
    OTHER = "other"


# event_type → (class, producer_id)
_EVENT_TYPE_MAP: dict[str, tuple[EvidenceClass, str]] = {
    "investigation_finding": (EvidenceClass.FINDING, "claim_graph"),
    "process_execution": (EvidenceClass.EXECUTION, "security_4688"),
    "process_termination": (EvidenceClass.EXECUTION, "security_4689"),
    "successful_logon": (EvidenceClass.AUTHENTICATION, "security_4624"),
    "failed_logon": (EvidenceClass.AUTHENTICATION, "security_4625"),
    "network_logon": (EvidenceClass.AUTHENTICATION, "security_4624_network"),
    "explicit_credential_logon": (EvidenceClass.AUTHENTICATION, "security_4648"),
    "user_logoff": (EvidenceClass.AUTHENTICATION, "security_4634"),
    "special_privileges": (EvidenceClass.AUTHENTICATION, "security_4672"),
    "privilege_escalation": (EvidenceClass.AUTHENTICATION, "security_4672"),
    "session_activity": (EvidenceClass.USER_INTERACTION, "session_table"),
    "file_accessed": (EvidenceClass.FILE_PRESENCE, "file_access"),
    "file_modified": (EvidenceClass.FILE_MODIFICATION, "file_modify"),
    "file_created": (EvidenceClass.FILE_PRESENCE, "file_create"),
    "executable_created": (EvidenceClass.FILE_PRESENCE, "exe_create"),
    "executable_deleted": (EvidenceClass.FILE_DELETION, "exe_delete"),
    "network_share_access": (EvidenceClass.NETWORK, "security_5140"),
    "network_connection": (EvidenceClass.NETWORK, "sysmon_3"),
    "scheduled_task_created": (EvidenceClass.PERSISTENCE, "security_4698"),
    "persistence_run_key": (EvidenceClass.PERSISTENCE, "run_key"),
    "persistence_service": (EvidenceClass.PERSISTENCE, "service"),
    "persistence_scheduled_task": (EvidenceClass.PERSISTENCE, "scheduled_task"),
    "powershell_activity": (EvidenceClass.COMMAND_EXECUTION, "powershell"),
    "office_document": (EvidenceClass.USER_INTERACTION, "office"),
    "usb_activity": (EvidenceClass.USB_DEVICE, "usb"),
    "remote_access": (EvidenceClass.LATERAL_REMOTE, "remote_access"),
    "lateral_movement": (EvidenceClass.LATERAL_REMOTE, "lateral"),
    "security_policy_change": (EvidenceClass.POLICY, "policy"),
    "event_chain_summary": (EvidenceClass.OTHER, "chain_summary"),
}

# Keywords in claim/finding prose → asserted evidence classes.
_CLASS_KEYWORDS: list[tuple[EvidenceClass, re.Pattern[str]]] = [
    (EvidenceClass.USB_DEVICE, re.compile(
        r"\b(?:usb|usbstor|setupapi|removable\s+media|"
        r"thumb\s*drive|flash\s*drive|badusb|hid\s+device)\b", re.I)),
    (EvidenceClass.AUTHENTICATION, re.compile(
        r"\b(?:logon|login|log\s*on|4624|4625|4648|kerberos|ntlm|"
        r"rdp|ssh|mfa|authentication|credential|password\s+spray|"
        r"failed\s+(?:logon|login)|successful\s+(?:logon|login))\b", re.I)),
    (EvidenceClass.EXECUTION, re.compile(
        r"\b(?:prefetch|amcache|shimcache|appcompat|bam|dam|userassist|"
        r"4688|sysmon|process\s+creat|executed|ran\s+|launched|"
        r"malware|payload|implant)\b", re.I)),
    (EvidenceClass.COMMAND_EXECUTION, re.compile(
        r"\b(?:powershell|cmd\.exe|pwsh|psreadline|wmi\s+activity|"
        r"scheduled\s+task\s+ran|command\s+line)\b", re.I)),
    (EvidenceClass.PERSISTENCE, re.compile(
        r"\b(?:persist|run\s*key|runonce|startup|scheduled\s+task|"
        r"windows\s+service|wmi\s+event|ifeo|appinit|winlogon|"
        r"com\s+hijack|autoruns?)\b", re.I)),
    (EvidenceClass.NETWORK, re.compile(
        r"\b(?:network|dns|proxy|vpn|netflow|pcap|firewall|"
        r"c2|beacon|exfil|outbound|sysmon\s*(?:eid\s*)?3)\b", re.I)),
    (EvidenceClass.LATERAL_REMOTE, re.compile(
        r"\b(?:lateral|psexec|wmiexec|rdp|remote\s+desktop|ssh|"
        r"winrm|smb\s+admin|admin\$)\b", re.I)),
    (EvidenceClass.FILE_PRESENCE, re.compile(
        r"\b(?:\$mft|mft\b|usn|dropped\s+file|file\s+created|"
        r"artifact\s+path|\.exe\b|\.dll\b)\b", re.I)),
    (EvidenceClass.FILE_MODIFICATION, re.compile(
        r"\b(?:timestomp|modified\s+file|usn\s+journal|"
        r"last\s+write|file\s+modif)\b", re.I)),
    (EvidenceClass.FILE_DELETION, re.compile(
        r"\b(?:deleted|recycle\s*bin|\$i:|\$r:|unallocated|"
        r"file\s+carv)\b", re.I)),
    (EvidenceClass.USER_INTERACTION, re.compile(
        r"\b(?:userassist|jump\s*list|lnk\b|recentdocs|shellbag|"
        r"browser\s+history|typedurls|runmru|remote\s+session|"
        r"interactive\s+session)\b", re.I)),
    (EvidenceClass.MALWARE_EXECUTION, re.compile(
        r"\b(?:malware|ransomware|trojan|backdoor|beacon|c2|"
        r"antivirus|edr\s+alert|yara\s+hit)\b", re.I)),
    (EvidenceClass.POLICY, re.compile(
        r"\b(?:audit\s+policy|security\s+policy|event\s+log\s+cleared|"
        r"4719|1102)\b", re.I)),
]

# High-volume types: keep via entity match / asserted class / aggregation,
# never via "host alone".
VOLUME_EVENT_TYPES = frozenset({
    "process_execution",
    "process_termination",
    "session_activity",
    "file_accessed",
    "file_modified",
    "file_created",
    "special_privileges",
    "privilege_escalation",
    "network_share_access",
    "successful_logon",
    "failed_logon",
    "network_logon",
    "explicit_credential_logon",
    "user_logoff",
})

# Types that corroborate strongly when host matches + class asserted
# (or always when principal matches).
CORROBORATIVE_EVENT_TYPES = frozenset({
    "usb_activity",
    "remote_access",
    "lateral_movement",
    "security_policy_change",
    "persistence_run_key",
    "persistence_service",
    "persistence_scheduled_task",
    "scheduled_task_created",
    "powershell_activity",
    "executable_created",
    "executable_deleted",
    "network_connection",
})

# Types that may be summarized (storm aggregation).
AGGREGATABLE_EVENT_TYPES = frozenset({
    "failed_logon",
    "successful_logon",
    "network_logon",
    "process_execution",
    "session_activity",
    "file_accessed",
    "network_share_access",
})


def classify_event(
    event_type: str,
    *,
    source_identifier: str = "",
    source_artifact: str = "",
    title: str = "",
) -> tuple[EvidenceClass, str]:
    """Return (evidence_class, producer_id) for a normalized event."""
    blob = f"{source_identifier} {source_artifact} {title}".lower()
    # Artifact-specific producers win over generic event_type mapping so
    # Prefetch/Amcache/Sysmon stay distinct perspectives of "execution".
    if "prefetch" in blob:
        return EvidenceClass.EXECUTION, "prefetch"
    if "amcache" in blob:
        return EvidenceClass.EXECUTION, "amcache"
    if "shimcache" in blob or "appcompat" in blob:
        return EvidenceClass.EXECUTION, "shimcache"
    if "userassist" in blob:
        return EvidenceClass.USER_INTERACTION, "userassist"
    if "setupapi" in blob or "usbstor" in blob:
        return EvidenceClass.USB_DEVICE, "usb"
    if "sysmon" in blob and (
            "eid 1" in blob or "event id 1" in blob or "/1" in blob):
        return EvidenceClass.EXECUTION, "sysmon_1"
    if "powershell" in blob or "psreadline" in blob:
        return EvidenceClass.COMMAND_EXECUTION, "powershell"
    if "mft" in blob or "$mft" in blob:
        return EvidenceClass.FILE_PRESENCE, "mft"
    if "usn" in blob:
        return EvidenceClass.FILE_MODIFICATION, "usn"

    et = (event_type or "").strip()
    if et in _EVENT_TYPE_MAP:
        return _EVENT_TYPE_MAP[et]
    return EvidenceClass.OTHER, et or "unknown"


def classes_from_narrative(texts: Iterable[str]) -> set[EvidenceClass]:
    """Infer which evidence classes the investigation narrative asserts."""
    blob = "\n".join(t for t in texts if t)
    found: set[EvidenceClass] = set()
    if not blob.strip():
        return found
    for cls, pat in _CLASS_KEYWORDS:
        if pat.search(blob):
            found.add(cls)
    return found


def narrative_texts_from_case(case_dir) -> list[str]:
    """Pull claim statements (+ optional finding index) for class inference."""
    from pathlib import Path
    import json

    root = Path(case_dir)
    texts: list[str] = []
    cg = root / ".atlas" / "claim_graph.json"
    if cg.is_file():
        try:
            data = json.loads(cg.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        nodes = data.get("nodes") or {}
        for node in nodes.values() if isinstance(nodes, dict) else []:
            if not isinstance(node, dict):
                continue
            if (node.get("kind") or "claim") != "claim":
                continue
            if (node.get("status") or "").lower() == "superseded":
                continue
            texts.append(str(node.get("statement") or ""))
            texts.append(str(node.get("reasoning") or ""))
    fi = root / ".atlas" / "finding_index.json"
    if fi.is_file():
        try:
            data = json.loads(fi.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        for ent in (data.get("findings") or data.get("entries") or []):
            if isinstance(ent, dict):
                texts.append(str(ent.get("statement") or ""))
                texts.append(str(ent.get("description") or ""))
    return texts
