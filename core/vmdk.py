"""VMDK descriptor and snapshot-chain parsing (stdlib only).

Why this exists: when a VMware disk has snapshots, the base extent
(``X-flat.vmdk``) is FROZEN at the moment the first snapshot was taken —
every later write goes to the delta extents (``X-000001-delta.vmdk``, …).
Analyzing the flat extent therefore shows the pre-snapshot state of the
disk, which reads like "the system was last active on <snapshot date>".

The parser is intentionally read-cheap for network-mounted evidence: it
reads descriptor text (a few KB), the sparse-extent header when the
descriptor is embedded, and stat() results — never extent data.
"""
from __future__ import annotations

import datetime as _dt
import os
import re
import struct

# parentCID value meaning "no parent" (base disk).
NO_PARENT_CID = "ffffffff"

# Filenames like VM01-000001.vmdk are snapshot delta descriptors;
# VM01-000001-delta.vmdk / -sesparse.vmdk are their data extents.
_DELTA_NAME_RE = re.compile(r"-(\d{6})(?:-(?:delta|sesparse))?\.vmdk$",
                            re.IGNORECASE)
_FLAT_NAME_RE = re.compile(r"-flat\.vmdk$", re.IGNORECASE)

_DESCRIPTOR_MAGIC = b"# Disk DescriptorFile"
_SPARSE_MAGIC_KDMV = b"KDMV"   # hosted sparse extent (embedded descriptor)
_SPARSE_MAGIC_COWD = b"COWD"   # ESX COW delta extent (descriptor is a sibling)

_EXTENT_RE = re.compile(
    r'^\s*(RW|RDONLY|NOACCESS)\s+(\d+)\s+([A-Z]+)\s+"([^"]+)"(?:\s+(\d+))?',
    re.MULTILINE)
_KV_RE = re.compile(r'^\s*([\w.:]+)\s*=\s*"?([^"\r\n]*)"?\s*$', re.MULTILINE)


def read_descriptor_text(path: str, max_bytes: int = 65536) -> str:
    """Descriptor text of a .vmdk file, or "" when none can be located.

    Handles both layouts: standalone text descriptors (ESX style — the
    small ``X.vmdk`` next to ``X-flat.vmdk``) and hosted sparse extents
    with the descriptor embedded after the KDMV header.
    """
    try:
        with open(path, "rb") as f:
            head = f.read(1024)
            if not head:
                return ""
            if head.lstrip()[:len(_DESCRIPTOR_MAGIC)] == _DESCRIPTOR_MAGIC:
                rest = head + f.read(max_bytes - len(head))
                return rest.split(b"\x00", 1)[0].decode("utf-8", "replace")
            if head[:4] == _SPARSE_MAGIC_KDMV and len(head) >= 44:
                # SparseExtentHeader: magic(4) version(4) flags(4)
                # capacity(8) grainSize(8) descriptorOffset(8)
                # descriptorSize(8) — offsets/sizes in 512-byte sectors.
                desc_off, desc_size = struct.unpack_from("<QQ", head, 28)
                if not desc_size:
                    return ""
                f.seek(desc_off * 512)
                raw = f.read(min(desc_size * 512, max_bytes))
                return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
    except OSError:
        return ""
    return ""


def parse_descriptor(text: str) -> dict:
    """Parse VMDK descriptor text into cid / parent / createType / extents."""
    kv = {}
    for m in _KV_RE.finditer(text):
        key = m.group(1)
        if key.lower().startswith("ddb."):
            continue
        kv[key] = m.group(2).strip()
    extents = [
        {"access": m.group(1), "sectors": int(m.group(2)),
         "type": m.group(3), "filename": m.group(4)}
        for m in _EXTENT_RE.finditer(text)
    ]
    parent_cid = kv.get("parentCID", NO_PARENT_CID).lower()
    return {
        "cid": kv.get("CID", "").lower(),
        "parent_cid": parent_cid,
        "has_parent": parent_cid not in ("", NO_PARENT_CID),
        "create_type": kv.get("createType", ""),
        "parent_hint": os.path.basename(
            kv.get("parentFileNameHint", "").replace("\\", "/")),
        "extents": extents,
    }


def parse_vmsd(text: str) -> list[dict]:
    """Snapshot metadata from a .vmsd file: name, creation time, disks."""
    kv = {m.group(1): m.group(2).strip() for m in _KV_RE.finditer(text)}
    snaps = []
    indices = sorted({
        int(m.group(1)) for k in kv
        if (m := re.match(r"snapshot(\d+)\.", k))
    })
    for i in indices:
        pre = f"snapshot{i}."
        created = ""
        try:
            high = int(kv.get(pre + "createTimeHigh", ""))
            low = int(kv.get(pre + "createTimeLow", ""))
            micros = (high << 32) | (low & 0xFFFFFFFF)
            created = _dt.datetime.fromtimestamp(
                micros / 1_000_000, tz=_dt.timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (ValueError, TypeError, OSError, OverflowError):
            pass
        disks = []
        d = 0
        while pre + f"disk{d}.fileName" in kv:
            disks.append(os.path.basename(
                kv[pre + f"disk{d}.fileName"].replace("\\", "/")))
            d += 1
        snaps.append({
            "uid": kv.get(pre + "uid", ""),
            "display_name": kv.get(pre + "displayName", ""),
            "created_utc": created,
            "disks": disks,
        })
    return snaps


def parse_vmx_disks(text: str) -> list[str]:
    """Disk descriptors the VM configuration currently attaches (basenames)."""
    kv = {m.group(1).lower(): m.group(2).strip()
          for m in _KV_RE.finditer(text)}
    disks = []
    for key, value in kv.items():
        m = re.match(r"(scsi|ide|sata|nvme)(\d+):(\d+)\.filename$", key)
        if not m or not value.lower().endswith(".vmdk"):
            continue
        present = kv.get(f"{m.group(1)}{m.group(2)}:{m.group(3)}.present",
                         "true")
        if present.lower() == "false":
            continue
        disks.append(os.path.basename(value.replace("\\", "/")))
    return sorted(set(disks))


def sibling_deltas(vmdk_path: str) -> list[str]:
    """Snapshot-delta descriptors that shadow the given base .vmdk.

    Filename-heuristic only (one listdir, no descriptor reads) so it is
    safe to call from hot paths on network-mounted evidence: for base
    ``X.vmdk`` / ``X-flat.vmdk``, any sibling ``X-NNNNNN.vmdk`` is a
    snapshot delta of that disk. Returns [] when the path itself already
    names a delta (``X-NNNNNN*.vmdk``).
    """
    # realpath (not abspath): evidence is routinely a symlink — the VM dir
    # symlinked to a network share, or misc.symlink_evidence's ASCII-safe
    # file link under analysis/. abspath keeps the symlink's own directory
    # (which holds no delta siblings), so the frozen-base check the whole
    # gate exists for would silently miss.
    real = os.path.realpath(os.path.expanduser(vmdk_path))
    base = os.path.basename(real)
    if _DELTA_NAME_RE.search(base):
        return []
    stem = _FLAT_NAME_RE.sub("", base)
    if stem == base:
        stem = re.sub(r"\.vmdk$", "", base, flags=re.IGNORECASE)
    try:
        names = os.listdir(os.path.dirname(real))
    except OSError:
        return []
    out = []
    for name in names:
        m = _DELTA_NAME_RE.search(name)
        if not m or name.lower().startswith(stem.lower() + "-") is False:
            continue
        if name[:len(stem)].lower() == stem.lower() \
                and re.fullmatch(r"-\d{6}\.vmdk", name[len(stem):],
                                 re.IGNORECASE):
            out.append(name)
    return sorted(out)


def snapshot_warning(vmdk_path: str) -> str:
    """One-line warning when a base VMDK is shadowed by snapshot deltas.

    Empty string when the path has no deltas (or isn't a base vmdk).
    """
    deltas = sibling_deltas(vmdk_path)
    if not deltas:
        return ""
    return (
        f"VMDK SNAPSHOT CHAIN: {os.path.basename(vmdk_path)} is a BASE disk "
        f"shadowed by {len(deltas)} snapshot delta(s) ({', '.join(deltas)}). "
        "The base/-flat extent is FROZEN at the oldest snapshot's creation "
        "time — all later writes (and any later attacker activity) exist "
        "ONLY in the delta chain. Run img_vmdk_chain_info on the VM "
        "directory and analyze the ACTIVE chain-top descriptor instead "
        "(chain-aware openers: img_vmdk_export_raw / qemu-nbd / pyvmdk — "
        "TSK and xmount can NOT open VMDK snapshot chains directly); never "
        "conclude 'no activity after <date>' from the base extent."
    )


def _stat_or_none(path: str) -> os.stat_result | None:
    try:
        return os.stat(path)
    except OSError:
        return None


def analyze_vm_dir(directory: str) -> dict:
    """Full snapshot-chain report for a VMware VM directory."""
    # realpath: the VM directory is often a symlink to network storage.
    directory = os.path.realpath(os.path.expanduser(directory))
    try:
        names = sorted(os.listdir(directory))
    except OSError as e:
        return {"success": False, "error": str(e), "directory": directory}

    descriptors: dict[str, dict] = {}
    for name in names:
        if not name.lower().endswith(".vmdk"):
            continue
        if _FLAT_NAME_RE.search(name) or re.search(
                r"-(?:delta|sesparse)\.vmdk$", name, re.IGNORECASE):
            continue  # data extents; their descriptor is a sibling
        path = os.path.join(directory, name)
        text = read_descriptor_text(path)
        if not text:
            continue
        desc = parse_descriptor(text)
        st = _stat_or_none(path)
        extent_info = []
        for ext in desc["extents"]:
            est = _stat_or_none(os.path.join(directory, ext["filename"]))
            extent_info.append({
                **ext,
                "size_bytes": est.st_size if est else None,
                "modified_utc": _dt.datetime.fromtimestamp(
                    est.st_mtime, tz=_dt.timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S UTC") if est else None,
            })
        desc["extents"] = extent_info
        desc["descriptor_modified_utc"] = _dt.datetime.fromtimestamp(
            st.st_mtime, tz=_dt.timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC") if st else None
        descriptors[name] = desc

    # Resolve parent links: parentFileNameHint first, CID match as fallback.
    parents: dict[str, str] = {}
    broken: list[str] = []
    for name, desc in descriptors.items():
        if not desc["has_parent"]:
            continue
        hint = desc["parent_hint"]
        if hint and hint in descriptors:
            parents[name] = hint
            continue
        by_cid = [n for n, d in descriptors.items()
                  if n != name and d["cid"] == desc["parent_cid"]]
        if len(by_cid) == 1:
            parents[name] = by_cid[0]
        else:
            broken.append(
                f"{name}: parent '{hint or desc['parent_cid']}' not found "
                f"in {directory}")

    referenced_as_parent = set(parents.values())
    chains = []
    for name, desc in descriptors.items():
        if name in referenced_as_parent:
            continue
        chain, cur, seen = [], name, set()
        while cur and cur not in seen:
            seen.add(cur)
            chain.append(cur)
            cur = parents.get(cur, "")
        chains.append(chain)

    snapshots: list[dict] = []
    active_disks: list[str] = []
    for name in names:
        path = os.path.join(directory, name)
        try:
            if name.lower().endswith(".vmsd"):
                snapshots.extend(parse_vmsd(
                    open(path, encoding="utf-8", errors="replace").read()))
            elif name.lower().endswith(".vmx"):
                active_disks.extend(parse_vmx_disks(
                    open(path, encoding="utf-8", errors="replace").read()))
        except OSError:
            continue

    warnings = []
    targets = []
    for chain in chains:
        top, base = chain[0], chain[-1]
        has_deltas = len(chain) > 1
        targets.append({
            "recommended_descriptor": os.path.join(directory, top),
            "chain_top_to_base": chain,
            "base_descriptor": base,
            "base_frozen": has_deltas,
            "vmx_attached": top in active_disks,
        })
        if has_deltas:
            snap_dates = ", ".join(
                f"'{s['display_name']}' {s['created_utc']}"
                for s in snapshots if s["created_utc"]) or "unknown date(s)"
            warnings.append(
                f"Disk '{base}': {len(chain) - 1} snapshot delta(s) on top "
                f"of the base (snapshots: {snap_dates}). The base/-flat "
                f"extent is FROZEN at the oldest snapshot's creation time; "
                f"activity after that exists ONLY in the deltas. Analyze "
                f"via the chain-top descriptor '{top}' with a chain-aware "
                f"opener (img_vmdk_export_raw / qemu-nbd / pyvmdk; TSK and "
                f"xmount cannot open VMDK chains directly) — a finding "
                f"of 'no activity after <date>' from the base extent alone "
                f"is an ANALYSIS ARTIFACT, not evidence.")
    for b in broken:
        warnings.append(f"Snapshot chain broken — {b}. The chain top cannot "
                        f"be opened without its parent; do not fall back to "
                        f"the base silently.")

    return {
        "success": True,
        "directory": directory,
        "descriptors": descriptors,
        "chains_top_to_base": chains,
        "snapshots": snapshots,
        "vmx_attached_disks": active_disks,
        "analysis_targets": targets,
        "warnings": warnings,
    }
