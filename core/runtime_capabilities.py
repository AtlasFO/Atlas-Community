"""Which tool opens a disk image, and when loop/FUSE mounts may run.

A disk image is oriented with The Sleuth Kit (tsk.mmls, then tsk.fls)
before anything mounts it: loop and FUSE mounts wait on sudo and stall on
multi-GB images, so during Triage they are refused until TSK has opened
the disk.
"""
from __future__ import annotations


def disk_open_tool_for_path(path: str) -> str:
    """Next-step disk-open tool for a concrete path."""
    lower = (path or "").lower()
    if lower.endswith(".vmdk"):
        return "img.vmdk_chain_info"
    if lower.endswith((".raw", ".dd", ".img", ".vhd", ".vhdx")):
        return "tsk.mmls"
    if lower.endswith((".e01", ".ex01")):
        return "ewf.mount_full_image"
    return "tsk.mmls"


# Loop/FUSE open tools — demoted in Triage until TSK orientation has run.
# Keep callable in Collect/Analyze (or after tsk.mmls/fls) for legitimate
# offset mounts; do not ban globally.
_LOOP_FUSE_OPEN_TOOLS = frozenset({
    "img_losetup_create",
    "img.losetup_create",
    "img_xmount_image",
    "img.xmount_image",
    "ewf_mount_ntfs",
    "ewf.mount_ntfs",
})

def is_loop_fuse_open_tool(tool_name: str) -> bool:
    n = (tool_name or "").strip()
    if not n:
        return False
    if n in _LOOP_FUSE_OPEN_TOOLS:
        return True
    # MCP names arrive as img_losetup_create; planning uses img.losetup_create
    underscored = n.replace(".", "_")
    dotted = n.replace("_", ".", 1) if n.startswith(("img_", "ewf_")) else n
    aliases = {t.replace(".", "_") for t in _LOOP_FUSE_OPEN_TOOLS}
    aliases |= set(_LOOP_FUSE_OPEN_TOOLS)
    return underscored in aliases or dotted in aliases


def tsk_disk_open_attempted(case_dir: str | None = None) -> bool:
    """True when disk media is opened (access stage) or TSK succeeded this process.

    Orientation for a mount, not the Access Stage's open: the partition
    table tsk.mmls lists is what an offset mount needs, so it counts here
    while it opens no media (core.evidence_access.is_tsk_open_tool)."""
    try:
        from core.evidence_access import any_media_opened
        if any_media_opened(case_dir):
            return True
    except Exception:
        pass
    try:
        from core.execution_log import log
        entries = list(getattr(log, "_entries", None) or [])
    except Exception:
        return False
    for e in entries:
        if e.get("type") != "tool_call" or not e.get("success"):
            continue
        blob = " ".join(
            str(e.get(k) or "") for k in ("mcp_tool", "tool", "cmd")
        ).casefold()
        if ("tsk_mmls" in blob or "tsk.mmls" in blob
                or "<py>:tsk_mmls" in blob):
            return True
        if ("tsk_fls" in blob or "tsk.fls" in blob
                or "<py>:tsk_fls" in blob):
            return True
    return False


def current_dair_phase() -> str:
    try:
        from core.execution_log import log
        return str(getattr(log, "_current_phase", "") or "")
    except Exception:
        return ""


def _export_raw_registered(case_dir: str | None) -> bool:
    """True when access stage still has a staged export_raw on disk."""
    try:
        from core.evidence_access import export_raw_registered
        return bool(export_raw_registered(case_dir))
    except Exception:
        return False


def loop_fuse_open_allowed(case_dir: str | None = None) -> bool:
    """Allow loop/FUSE open outside Triage, or after TSK orientation.

    While an export_raw is registered and TSK has not opened the disk
    yet, loop/FUSE stays demoted even after the phase moved on: tsk.mmls
    on a freshly flattened multi-GB raw beats burning sudo and a loop
    device on it.
    """
    if tsk_disk_open_attempted(case_dir):
        return True
    if _export_raw_registered(case_dir):
        return False
    phase = current_dair_phase()
    return phase in ("Collect", "Analyze", "Scan", "Report")


def loop_fuse_demotion_refusal(tool_name: str,
                               case_dir: str | None = None) -> dict | None:
    """Refuse Triage-default loop/FUSE open; steer to tsk.mmls."""
    if not is_loop_fuse_open_tool(tool_name):
        return None
    if loop_fuse_open_allowed(case_dir):
        return None
    return {
        "success": False,
        "gate": "disk_open_policy",
        "error": (
            f"{tool_name} is demoted during Triage until disk orientation "
            "via tsk.mmls (then tsk.fls). Loop/FUSE mounts (losetup/xmount/"
            "ewf.mount_ntfs) hang on sudo/password and multi-GB images — use "
            "tsk.mmls on the exported raw (see .atlas/mount_plan.json). "
            "Retry losetup/xmount only in Collect/Analyze after TSK open, "
            "or when a partition offset mount is explicitly required."
        ),
        "recommended_tool": "tsk.mmls",
    }
