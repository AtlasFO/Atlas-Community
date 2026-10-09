"""Automatic disk-image mount planning (and safe E01 auto-mount).

Builds ``.atlas/mount_plan.json`` from the evidence profile. Auto-executes
only unambiguous E01/Ex01 images (no BitLocker heuristics tripped) under
``<case>/mnt/<stem>/``, where ``stem`` is ``Path(first_segment).stem``
(e.g. ``disk.E01`` → ``disk``; ``.E02+`` are not separate plan entries).
Plane A catalogs/fingerprints ``evidence/`` before auto-mount runs.
VMDK / encrypted / ambiguous formats stay plan-only.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = "1.0"

from core.artifact_kind import is_ewf_continuation_segment

_E01_RE = re.compile(r"\.(e01|ex01)$", re.I)
# Any first segment of an Expert Witness set (disk, logical or SMART).
_EWF_IMAGE_RE = re.compile(r"\.(?:e01|ex01|l01|lx01|s01)$", re.I)
_VMDK_RE = re.compile(r"\.(vmdk)$", re.I)
_RAW_RE = re.compile(r"\.(raw|dd|img|iso|vhd|vhdx)$", re.I)
_BITLOCKER_HINT = re.compile(r"(?i)bitlocker|bde|fve")


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def mount_plan_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "mount_plan.json"


def load_mount_plan(case_dir: str | os.PathLike) -> dict[str, Any]:
    path = mount_plan_path(case_dir)
    if not path.is_file():
        return {
            "schema_version": SCHEMA_VERSION,
            "updated_at": None,
            "images": [],
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema_version": SCHEMA_VERSION, "images": []}
    if not isinstance(data, dict):
        return {"schema_version": SCHEMA_VERSION, "images": []}
    data.setdefault("images", [])
    return data


def save_mount_plan(case_dir: str | os.PathLike, plan: dict[str, Any]) -> Path:
    path = mount_plan_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    plan = dict(plan)
    plan["schema_version"] = SCHEMA_VERSION
    plan["updated_at"] = _utcnow()
    path.write_text(
        json.dumps(plan, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def _classify_image(path: Path) -> dict[str, Any]:
    name = path.name
    lower = name.lower()
    entry: dict[str, Any] = {
        "path": str(path),
        "basename": name,
        "stem": path.stem,
        "recommended_tool": None,
        "action": "plan_only",
        "reason": "",
    }
    # Non-disk containers (SRUM/EseDB/pagefile dumps) must not enter Access
    # Stage as disk media — they blocked READY/exit when treated as tsk.mmls.
    try:
        from core.artifact_kind import is_non_disk_container, media_role_for_path
        if is_non_disk_container(path):
            entry["image_type"] = "non_disk_artifact"
            entry["media_role"] = media_role_for_path(path)
            entry["access_gated"] = False
            entry["action"] = "skip"
            entry["recommended_tool"] = None
            entry["reason"] = (
                "not a disk image (application database / dump) — "
                "do not open with tsk.mmls; parse with the matching "
                "artifact tool or mark coverage blocked / access_failed"
            )
            return entry
    except Exception:
        pass
    # The first segment stands for a split set; ewfmount reads the rest.
    if is_ewf_continuation_segment(lower):
        entry["image_type"] = "ewf_segment"
        entry["media_role"] = "disk"
        entry["access_gated"] = False
        entry["action"] = "skip"
        entry["reason"] = ("continuation segment of a split EWF image — "
                           "opened together with its first segment (.E01)")
        return entry
    entry["access_gated"] = True
    entry["media_role"] = "disk"
    if _E01_RE.search(lower):
        entry["image_type"] = "ewf"
        entry["recommended_tool"] = "ewf.mount_full_image"
        if _BITLOCKER_HINT.search(name):
            entry["action"] = "plan_only"
            entry["reason"] = "BitLocker hint in filename — mount manually"
        else:
            entry["action"] = "auto_mount"
            entry["reason"] = "unambiguous E01/Ex01"
        return entry
    if _VMDK_RE.search(lower):
        entry["image_type"] = "vmdk"
        entry["recommended_tool"] = "img.vmdk_chain_info"
        entry["reason"] = (
            "VMDK — chain check then img.vmdk_export_raw → tsk.*/ez.* "
            "(do not Triage-default xmount)"
        )
        return entry
    if lower.endswith(".iso"):
        entry["image_type"] = "iso"
        entry["recommended_tool"] = "loop/cdemu (manual)"
        entry["reason"] = "ISO — plan only in V1"
        return entry
    if _RAW_RE.search(lower):
        entry["image_type"] = "raw_or_container"
        # Prefer TSK over FUSE/loop mounts (xmount/losetup) as the Triage default.
        entry["recommended_tool"] = "tsk.mmls"
        entry["reason"] = (
            "raw/container — tsk.mmls lists the volume offsets; tsk.fsstat or "
            "tsk.fls at a volume's offset_sectors opens it (avoid xmount/losetup "
            "as Triage default)"
        )
        return entry
    entry["image_type"] = "unknown"
    entry["reason"] = "not a recognized disk image extension"
    return entry


def is_ewf_image(path: str | os.PathLike) -> bool:
    """Whether ``path`` names the first segment of an Expert Witness image,
    a container the Sleuth Kit reads only through the libewf image type
    (which many builds lack) or through the raw device ewfmount exposes."""
    return bool(_EWF_IMAGE_RE.search(str(path or "")))


def _safe_stem(stem: str) -> str:
    return re.sub(r"[^\w.\-]+", "_", stem or "image")[:80]


def _mount_stem(entry: dict[str, Any] | None, image_path: str | os.PathLike = "") -> str:
    """The folder name under mnt/ an image mounts into: the plan's
    ``mount_stem``, else the safe stem of the image's name."""
    if entry and entry.get("mount_stem"):
        return str(entry["mount_stem"])
    stem = (entry or {}).get("stem") or Path(str(image_path)).stem
    return _safe_stem(stem or "image")


def _recorded_mount_stem(root: Path, entry: dict[str, Any]) -> str:
    """X when the plan recorded this image mounted at mnt/<X>/fs or exposed at
    mnt/<X>/ewf/ewf1 under this case."""
    mr = entry.get("mount_result") or {}
    mnt = os.path.realpath(str(root / "mnt"))
    for key, tail in (("mount_point", ("fs",)), ("ewf_device", ("ewf", "ewf1"))):
        rec = str(mr.get(key) or "")
        if not rec:
            continue
        rel = os.path.relpath(os.path.realpath(rec), mnt).split(os.sep)
        if len(rel) == 1 + len(tail) and tuple(rel[1:]) == tail and rel[0] not in ("", ".", ".."):
            return rel[0]
    return ""


def _assign_mount_stems(root: Path, images: list[dict[str, Any]]) -> None:
    """Give every image a folder of its own under mnt/. An image the plan
    recorded under mnt/<X>/ keeps X, so a live mount keeps its folder; any
    other takes the safe stem of its name when no other image of the plan
    has it, else that stem plus 8 hex digits of the sha1 of its real path,
    which is the same on every rebuild."""
    taken: set[str] = set()
    rest: list[dict[str, Any]] = []
    # A record the plan made by finding the folder already mounted ("reused")
    # yields to one that mounted it: two images of one name once shared a
    # folder that way, and only the second one's record says reused.
    by_reuse = sorted(images, key=lambda i: bool((i.get("mount_result") or {}).get("reused")))
    for img in by_reuse:
        rec = _recorded_mount_stem(root, img)
        if rec and rec not in taken:
            img["mount_stem"] = rec
            taken.add(rec)
        else:
            rest.append(img)
    rest.sort(key=images.index)
    counts: dict[str, int] = {}
    for img in rest:
        s = _safe_stem(img.get("stem") or "image")
        counts[s] = counts.get(s, 0) + 1
    for img in rest:
        s = _safe_stem(img.get("stem") or "image")
        if counts[s] > 1 or s in taken:
            real = os.path.realpath(os.path.abspath(os.path.expanduser(str(img.get("path") or s))))
            s = f"{s[:71]}-{hashlib.sha1(real.encode('utf-8')).hexdigest()[:8]}"
        img["mount_stem"] = s
        taken.add(s)


def mount_dir_for(case_dir: str | os.PathLike, image_path: str | os.PathLike,
                  entry: dict[str, Any] | None = None) -> str:
    """The directory the auto-mount convention gives an image
    (``mnt/<mount_stem>/`` holding ``ewf/`` and ``fs/``); pass the image's
    plan entry when it is at hand."""
    return str(Path(case_dir) / "mnt" / _mount_stem(entry, image_path))


def ewf_device_for(case_dir: str | os.PathLike | None,
                   image_path: str | os.PathLike) -> Optional[str]:
    """The raw device ewfmount exposes for an Expert Witness image, when it
    is mounted: the one the mount plan recorded, else the one the auto-mount
    convention (``mnt/<stem>/ewf/ewf1``) places. None when nothing exposes
    the image right now."""
    if not case_dir:
        return None
    root = Path(case_dir)
    target = os.path.abspath(os.path.expanduser(str(image_path)))
    base = os.path.basename(target)
    exact: list[dict[str, Any]] = []
    by_name: list[dict[str, Any]] = []
    try:
        for img in load_mount_plan(root).get("images") or []:
            ip = str(img.get("path") or "")
            if not ip:
                continue
            if os.path.abspath(os.path.expanduser(ip)) == target:
                exact.append(img)
            elif os.path.basename(ip) == base:
                by_name.append(img)
    except Exception:  # noqa: BLE001 - a missing plan leaves the convention path
        pass
    # A name alone identifies the image only when one image of the plan has it.
    matches = exact or (by_name if len(by_name) == 1 else [])
    candidates: list[str] = []
    for img in matches:
        dev = str((img.get("mount_result") or {}).get("ewf_device") or "")
        if dev:
            candidates.append(dev)
    for img in matches or [None]:
        candidates.append(str(root / "mnt" / _mount_stem(img, target) / "ewf" / "ewf1"))
    for dev in candidates:
        try:
            if os.path.isfile(dev) and os.path.getsize(dev) > 0:
                return dev
        except OSError:
            continue
    return None


def device_for_mount_point(case_dir: str | os.PathLike | None,
                           directory: str | os.PathLike) -> Optional[str]:
    """The raw device under a mounted filesystem directory: the mount plan's
    ewf device for the image whose filesystem is mounted there, else the
    convention sibling (``mnt/<stem>/fs`` beside ``mnt/<stem>/ewf/ewf1``).
    None when the directory is not a filesystem the plan mounted."""
    if not case_dir or not directory:
        return None
    real = os.path.realpath(os.path.expanduser(str(directory)))
    candidates: list[str] = []
    try:
        for img in load_mount_plan(case_dir).get("images") or []:
            mr = img.get("mount_result") or {}
            mp = str(mr.get("mount_point") or "")
            if mp and os.path.realpath(os.path.expanduser(mp)) == real and mr.get("ewf_device"):
                candidates.append(str(mr["ewf_device"]))
    except Exception:  # noqa: BLE001
        pass
    if os.path.basename(real) == "fs":
        candidates.append(os.path.join(os.path.dirname(real), "ewf", "ewf1"))
    for dev in candidates:
        try:
            if os.path.isfile(dev) and os.path.getsize(dev) > 0:
                return dev
        except OSError:
            continue
    return None


def _image_key(entry: dict[str, Any]) -> str:
    """Stable identity for merge: path, else export source basename."""
    path = str(entry.get("path") or "")
    if path:
        return os.path.abspath(os.path.expanduser(path))
    src = str(entry.get("source") or "")
    if src:
        return "source:" + os.path.basename(src)
    return ""


def _merge_prior_images(
    fresh: list[dict[str, Any]],
    prior: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge prior export/open records into a freshly scanned image list.

    Plane A rebuilds from evidence/ profile and previously dropped
    ``origin=export_raw`` analysis paths — keep those handoffs unless the
    backing file is gone (caller invalidates separately).
    """
    by_key: dict[str, dict[str, Any]] = {}
    for img in fresh:
        k = _image_key(img)
        if k:
            by_key[k] = dict(img)
    for old in prior:
        if not isinstance(old, dict):
            continue
        # Drop legacy non-disk rows that incorrectly entered Access Stage.
        try:
            from core.artifact_kind import is_non_disk_container
            if is_non_disk_container(str(old.get("path") or "")):
                continue
        except Exception:
            pass
        if old.get("access_gated") is False or old.get("action") == "skip":
            continue
        k = _image_key(old)
        if not k:
            continue
        if k in by_key:
            # Preserve durable access progress on the scanned entry.
            cur = by_key[k]
            for field in (
                "status", "origin", "source", "mount_result",
                "opened_tool", "opened_at", "access_error",
            ):
                if old.get(field) and not cur.get(field):
                    cur[field] = old[field]
            # Prefer richer status (opened > exported > plan_only).
            rank = {
                "opened": 5, "mounted": 5, "exported": 4, "staged": 4,
                "mount_failed": 3, "access_failed": 3, "open_failed": 3,
            }
            if rank.get(str(old.get("status")), 0) > rank.get(
                    str(cur.get("status")), 0):
                cur["status"] = old["status"]
            by_key[k] = cur
            continue
        # Prior-only (e.g. analysis/*.raw export) — keep if still useful.
        if old.get("origin") == "export_raw" or old.get("status") in (
            "exported", "opened", "mounted", "mount_failed", "access_failed",
        ):
            by_key[k] = dict(old)
    return list(by_key.values())


def invalidate_missing_media(
    case_dir: str | os.PathLike,
    *,
    persist: bool = True,
) -> dict[str, Any]:
    """Demote staged/opened entries whose backing files were wiped.

    Used by ``clear_case_run`` after deleting ``analysis/`` so mount_plan
    cannot claim ``exported`` for a missing raw.
    """
    root = Path(case_dir).resolve()
    plan = load_mount_plan(root)
    images = list(plan.get("images") or [])
    changed = 0
    kept: list[dict[str, Any]] = []
    for img in images:
        if not isinstance(img, dict):
            continue
        path_s = str(img.get("path") or "")
        p = Path(path_s) if path_s else None
        exists = bool(p and p.is_file())
        if not exists and path_s:
            cand = root / path_s
            exists = cand.is_file()
            if exists:
                p = cand
        st = str(img.get("status") or "")
        if not exists and st in (
            "exported", "mounted", "opened", "staged", "",
        ):
            # Drop orphan analysis exports entirely — they are not evidence/.
            if img.get("origin") == "export_raw":
                changed += 1
                continue
            img = dict(img)
            img["status"] = "absent"
            img["reason"] = (
                (img.get("reason") or "") + " [invalidated: file missing]"
            ).strip()
            changed += 1
        kept.append(img)
    plan["images"] = kept
    if persist and changed:
        save_mount_plan(root, plan)
    return {"success": True, "changed": changed, "images": kept}


def mark_image_opened(
    case_dir: str | os.PathLike,
    image_path: str | os.PathLike,
    *,
    tool: str = "tsk.fsstat",
    persist: bool = True,
) -> dict[str, Any]:
    """Record successful disk open (TSK / mount) on the access plan."""
    root = Path(case_dir).resolve()
    plan = load_mount_plan(root)
    images = list(plan.get("images") or [])
    target = os.path.abspath(os.path.expanduser(str(image_path)))
    base = os.path.basename(target)
    updated = False
    for i, img in enumerate(images):
        ip = str(img.get("path") or "")
        try:
            ip_abs = os.path.abspath(os.path.expanduser(ip)) if ip else ""
        except Exception:
            ip_abs = ip
        if ip_abs == target or os.path.basename(ip) == base:
            images[i] = {
                **img,
                "status": "opened",
                "opened_tool": tool,
                "opened_at": _utcnow(),
            }
            updated = True
            break
    if not updated:
        # Register a minimal opened entry so access stage is durable.
        p = Path(target)
        entry = _classify_image(p if p.exists() else Path(base))
        entry["path"] = target
        entry["status"] = "opened"
        entry["opened_tool"] = tool
        entry["opened_at"] = _utcnow()
        entry["action"] = "plan_only"
        images.append(entry)
    plan["images"] = images
    if persist:
        save_mount_plan(root, plan)
    return plan


def mark_image_access_failed(
    case_dir: str | os.PathLike,
    image_path: str | os.PathLike,
    *,
    error: str = "",
    tool: str = "",
    persist: bool = True,
) -> dict[str, Any]:
    """Record a failed open/mount attempt on the access plan."""
    root = Path(case_dir).resolve()
    plan = load_mount_plan(root)
    images = list(plan.get("images") or [])
    target = os.path.abspath(os.path.expanduser(str(image_path)))
    base = os.path.basename(target)
    for i, img in enumerate(images):
        ip = str(img.get("path") or "")
        try:
            ip_abs = os.path.abspath(os.path.expanduser(ip)) if ip else ""
        except Exception:
            ip_abs = ip
        if ip_abs == target or os.path.basename(ip) == base:
            images[i] = {
                **img,
                "status": "access_failed",
                "access_error": (error or "")[:400],
                "opened_tool": tool or img.get("opened_tool"),
                "opened_at": _utcnow(),
            }
            break
    plan["images"] = images
    if persist:
        save_mount_plan(root, plan)
    return plan


def plane_a_auto_mount_allowed() -> tuple[bool, str]:
    """Whether Plane A may execute privileged E01 auto-mount.

    ``ATLAS_PLANE_A_AUTO_MOUNT``:
      - ``off`` / ``0`` / ``false`` — never auto-mount (plan only)
      - ``on`` / ``1`` / ``force`` — attempt even if sudo probe fails
      - ``auto`` (default) — only when passwordless sudo is available

    Auto-mount is an architecture choice (privileged Plane A), not a silent
    convenience — see Max Q3b / architecture-case-driven.md.
    """
    raw = (os.environ.get("ATLAS_PLANE_A_AUTO_MOUNT") or "auto").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False, "ATLAS_PLANE_A_AUTO_MOUNT=off"
    if raw in ("1", "true", "yes", "on", "force"):
        return True, "ATLAS_PLANE_A_AUTO_MOUNT=force"
    # auto
    if (os.environ.get("ATLAS_SKIP_SUDO_CHECK") or "").strip().lower() in (
        "1", "true", "yes", "on",
    ):
        return True, "sudo_check_skipped"
    try:
        from core.sudo_preflight import check_passwordless_sudo
        ok, details = check_passwordless_sudo()
        if ok:
            return True, "sudo_ok"
        return False, "sudo_unavailable:" + ";".join(details[:2])
    except Exception as e:
        return False, f"sudo_check_error:{type(e).__name__}"


def _path_is_mounted(mount_point: str) -> bool:
    """True if mount_point appears as a mount target in /proc/mounts."""
    try:
        real = os.path.realpath(mount_point)
    except OSError:
        return False
    try:
        with open("/proc/mounts", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 2:
                    continue
                mp = parts[1].replace("\\040", " ")
                try:
                    if os.path.realpath(mp) == real:
                        return True
                except OSError:
                    if mp == mount_point:
                        return True
    except OSError:
        return False
    return False


_PROFILE_ROOTS = ("Users", "Documents and Settings")
_PROFILE_NAME_CAP = 64
_PROFILE_LIST_CAP = 20


def _profile_names(mount_point: str) -> tuple[str, list[str], int]:
    """``(profile root, directory names, total)`` on a mounted volume: one
    directory read per candidate root, spelled as the volume spells it.
    The names are evidence and a suspect controls them, so each is capped
    and stripped of characters that do not print, and the list is bounded
    with the total kept, so a reader knows when names were left out."""
    for root in _PROFILE_ROOTS:
        try:
            with os.scandir(mount_point) as it:
                match = next((e for e in it
                              if e.name.casefold() == root.casefold() and e.is_dir(follow_symlinks=False)), None)
        except OSError:
            return "", [], 0
        if match is None:
            continue
        names: list[str] = []
        total = 0
        try:
            with os.scandir(match.path) as it:
                for e in sorted(it, key=lambda x: x.name.casefold()):
                    try:
                        if not e.is_dir(follow_symlinks=False):
                            continue
                    except OSError:
                        continue
                    total += 1
                    if len(names) < _PROFILE_LIST_CAP:
                        clean = "".join(ch for ch in e.name if ch.isprintable())[:_PROFILE_NAME_CAP]
                        names.append(clean or "?")
        except OSError:
            return match.name, [], 0
        return match.name, names, total
    return "", [], 0


def mounted_volumes(case_dir: str | os.PathLike) -> list[dict[str, Any]]:
    """Every image the plan records as open, checked live rather than by
    the shape of a directory: ``mnt/<stem>/fs`` is created before a mount
    is attempted and a rebuilt plan keeps a prior ``mounted`` status, so
    after a reboot a resumed case holds an empty directory that would pass
    ``isdir``. A filesystem counts when its mount result succeeded and its
    mount point is in the mount table now; a device counts when the EWF
    mount behind it is. Each entry: ``stem``, ``basename``, ``image_type``,
    ``mount_point`` and ``rel`` (absolute and case-relative filesystem
    mount, empty when none is live), ``device`` and ``device_rel``
    (likewise), ``profile_root`` and ``profiles`` (the profile directory
    and its names, when a filesystem is live)."""
    root = Path(case_dir).resolve()
    out: list[dict[str, Any]] = []

    def _rel(p: str) -> str:
        try:
            return Path(p).resolve().relative_to(root).as_posix()
        except (ValueError, OSError):
            return p

    images = [img for img in load_mount_plan(root).get("images") or [] if isinstance(img, dict)]
    # Two images named alike map to one mount directory and the plan records
    # the second as a reuse of the first: one line per mount point, the entry
    # that was not reused first, and a label that tells the two apart.
    names = [str(img.get("basename") or Path(str(img.get("path") or "")).name) for img in images]
    dup_names = {n for n in names if names.count(n) > 1}
    images.sort(key=lambda img: bool((img.get("mount_result") or {}).get("reused")))
    seen_points: set[str] = set()
    for img in images:
        if not isinstance(img, dict):
            continue
        result = img.get("mount_result") or {}
        point = str(result.get("mount_point") or "")
        live_fs = bool(result.get("success")) and bool(point) and _path_is_mounted(point)
        device = str(result.get("ewf_device") or "")
        live_dev = bool(device) and _path_is_mounted(os.path.dirname(device))
        if not live_fs and not live_dev:
            continue
        key = point if live_fs else device
        if key in seen_points:
            continue
        seen_points.add(key)
        stem = str(img.get("stem") or (Path(point).parent.name if point else "")
                   or Path(str(img.get("path") or "image")).stem)
        basename = str(img.get("basename") or Path(str(img.get("path") or "")).name)
        if basename in dup_names and img.get("path"):
            basename = _rel(str(img["path"]))
        entry = {
            "stem": stem,
            "path": str(img.get("path") or ""),
            "basename": basename,
            "image_type": str(img.get("image_type") or ""),
            "mount_point": point if live_fs else "",
            "rel": _rel(point) if live_fs else "",
            "device": device if live_dev else "",
            "device_rel": _rel(device) if live_dev else "",
            "profile_root": "",
            "profiles": [],
            "profile_total": 0,
        }
        if live_fs:
            entry["profile_root"], entry["profiles"], entry["profile_total"] = _profile_names(point)
        out.append(entry)
    return out


def _preflight_hash_before_mount(path: str) -> dict[str, Any]:
    """Custody fingerprint before auto-mount (sampled OK for large images)."""
    try:
        from tools.hashing import verify_evidence_hash
        result = verify_evidence_hash(path)
        out = {
            "success": bool(result.get("success")),
            "full_hash": result.get("full_hash"),
            "deferred": result.get("deferred"),
            "md5": result.get("md5") or result.get("sampled_sha256"),
            "error": result.get("error") or result.get("stderr"),
        }
        # The image's own integrity statement, when it carries one.
        for key in ("acquisition_hashes", "acquisition_verified", "media_size_bytes"):
            if result.get(key) is not None:
                out[key] = result[key]
        return out
    except Exception as e:
        return {"success": False, "error": str(e)[:200]}


def build_mount_plan(
    case_dir: str | os.PathLike,
    *,
    persist: bool = True,
    auto_mount: bool = True,
) -> dict[str, Any]:
    """Scan evidence profile for disk images; optionally auto-mount E01s."""
    root = Path(case_dir).resolve()
    prior_plan = load_mount_plan(root)
    prior = list(prior_plan.get("images") or [])
    images: list[dict[str, Any]] = []

    try:
        from core.evidence_profile import ensure_evidence_profile
        profile = ensure_evidence_profile(root)
    except Exception:
        profile = {"files": []}

    seen: set[str] = set()
    for f in profile.get("files") or []:
        if not isinstance(f, dict):
            continue
        if f.get("class") != "disk":
            # Also catch E01s mis-tagged if present by extension
            p = f.get("path") or ""
            if not _E01_RE.search(p) and not _VMDK_RE.search(p):
                continue
        path_s = f.get("path") or ""
        if not path_s or path_s in seen:
            continue
        seen.add(path_s)
        p = Path(path_s)
        if not p.is_file():
            # relative to case
            cand = root / path_s
            if cand.is_file():
                p = cand
            else:
                continue
        classified = _classify_image(p)
        if classified.get("access_gated") is False or classified.get("action") == "skip":
            continue
        images.append(classified)

    # Fallback walk if profile empty of disk. A file the evidence classifier
    # does not call a disk (a memory image by its header or by the brief's
    # declaration) is not disk media, whatever its name.
    if not images:
        ev = root / "evidence"
        if ev.is_dir():
            from core.evidence_profile import classify_path, declared_kinds
            declared = declared_kinds(root)
            for p in sorted(ev.rglob("*")):
                if not p.is_file():
                    continue
                if _E01_RE.search(p.name) or _VMDK_RE.search(p.name) or _RAW_RE.search(p.name):
                    if str(p) in seen:
                        continue
                    seen.add(str(p))
                    rel = p.relative_to(root).as_posix()
                    if classify_path(p, declared.get(rel, "")) != "disk":
                        continue
                    classified = _classify_image(p)
                    if classified.get("access_gated") is False or classified.get("action") == "skip":
                        continue
                    images.append(classified)

    # Preserve export/open handoffs that evidence/ scans miss.
    images = _merge_prior_images(images, prior)
    _assign_mount_stems(root, images)

    mounted: list[dict[str, Any]] = []
    errors: list[str] = []
    soft_notes: list[str] = []

    # A merged "mounted" is the prior plan's word; after a reboot or an
    # unmount the folder is empty. Such an entry loses the status, so the
    # loop below mounts it again, or, with auto-mount off, the plan stops
    # claiming it. "opened" records a tool that opened the image, not a mount.
    for entry in images:
        if entry.get("status") != "mounted":
            continue
        mr = entry.get("mount_result") or {}
        mp = str(mr.get("mount_point") or root / "mnt" / _mount_stem(entry) / "fs")
        if _path_is_mounted(mp):
            continue
        entry.pop("status", None)
        entry["mount_result"] = {**mr, "success": False, "stale": True}
        soft_notes.append(f"remount:{entry.get('basename') or entry.get('path')}")
    # An "opened" recorded by a call that opens no filesystem (a partition-
    # table read) loses the status: the image still waits for its open
    # (core.evidence_access.is_tsk_open_tool).
    from core.evidence_access import is_tsk_open_tool
    for entry in images:
        tool = str(entry.get("opened_tool") or "")
        if entry.get("status") == "opened" and tool and not is_tsk_open_tool(tool):
            for key in ("status", "opened_tool", "opened_at"):
                entry.pop(key, None)
            soft_notes.append(f"reopen:{entry.get('basename') or entry.get('path')}")
    auto_policy = ""
    do_auto = bool(auto_mount)
    if do_auto:
        allowed, auto_policy = plane_a_auto_mount_allowed()
        if not allowed:
            do_auto = False
            soft_notes.append(f"auto_mount_skipped:{auto_policy}")

    if do_auto:
        for entry in images:
            if entry.get("action") != "auto_mount":
                continue
            # Do not re-auto-mount already opened/mounted images.
            if entry.get("status") in ("mounted", "opened"):
                mounted.append(entry)
                continue
            stem = _mount_stem(entry)
            fs_mp = str(root / "mnt" / stem / "fs")
            if _path_is_mounted(fs_mp):
                entry["status"] = "mounted"
                entry["mount_result"] = {
                    "success": True,
                    "reused": True,
                    "mount_point": fs_mp,
                    "ewf_device": str(root / "mnt" / stem / "ewf" / "ewf1"),
                }
                mounted.append(entry)
                soft_notes.append(f"reused_mount:{entry.get('basename')}")
                continue
            try:
                result = _auto_mount_e01(root, entry)
                entry["hash_preflight"] = result.get("hash_preflight")
                entry["mount_result"] = {
                    "success": result.get("success"),
                    "mount_point": result.get("mount_point") or result.get("ntfs_mount"),
                    "error": result.get("error") or result.get("stderr"),
                    "gate": result.get("gate"),
                    "reused": result.get("reused") or result.get("ewf_reused"),
                    # The raw device stays exposed even when the filesystem
                    # mount failed (a non-NTFS volume): TSK reads it there.
                    "ewf_device": result.get("ewf_device"),
                }
                if result.get("success"):
                    entry["status"] = "mounted"
                    mounted.append(entry)
                elif result.get("gate") == "non_ntfs":
                    # Graceful: EWF may be up; FS auto-mount is NTFS-only.
                    entry["status"] = "plan_only"
                    entry["action"] = "plan_only"
                    entry["reason"] = (
                        "auto-mount: no NTFS partition — use tsk.*/plaso on "
                        "EWF device or image (not a Plane A hard failure)"
                    )
                    soft_notes.append(
                        f"non_ntfs:{entry.get('basename') or entry.get('path')}"
                    )
                else:
                    entry["status"] = "mount_failed"
                    errors.append(
                        str(result.get("error") or result.get("stderr")
                            or "mount failed")[:300]
                    )
            except Exception as e:
                entry["status"] = "mount_failed"
                entry["mount_result"] = {"success": False, "error": str(e)[:300]}
                errors.append(str(e)[:300])

    plan = {
        "schema_version": SCHEMA_VERSION,
        "case_id": root.name,
        "updated_at": _utcnow(),
        "images": images,
        "auto_mounted": [m.get("path") for m in mounted],
        "errors": errors,
        "soft_notes": soft_notes,
        "auto_mount_policy": auto_policy or (
            "caller_disabled" if not auto_mount else ""
        ),
        "note": (
            "Auto-mount only for unambiguous E01/Ex01 under case/mnt/ when "
            "ATLAS_PLANE_A_AUTO_MOUNT allows and sudo is available (default "
            "auto). Hash preflight runs first. Non-NTFS → plan_only (soft). "
            "VMDK/ISO/raw/encrypted/non-disk remain plan-only/skip. "
            "case/mnt is a protected path segment."
        ),
    }
    # The offset a filesystem tool succeeded at (note_volume_offset) stays
    # the default for an image that is still there.
    offsets = {k: v for k, v in (prior_plan.get("volume_offsets") or {}).items()
               if os.path.exists(k)}
    if offsets:
        plan["volume_offsets"] = offsets
    if persist:
        save_mount_plan(root, plan)
        # Drop/demote entries whose files vanished (e.g. after partial clears).
        invalidate_missing_media(root, persist=True)
        plan = load_mount_plan(root)
    return plan


def _auto_mount_e01(case_dir: Path, entry: dict[str, Any]) -> dict[str, Any]:
    """Mount one E01 under case/mnt/<mount_stem>/{ewf,fs}/ using
    ewf.mount_full_image.

    Runs hash.verify_evidence_hash first (sampled fingerprint OK).
    """
    stem = _mount_stem(entry)
    ewf_mp = case_dir / "mnt" / stem / "ewf"
    fs_mp = case_dir / "mnt" / stem / "fs"
    ewf_mp.mkdir(parents=True, exist_ok=True)
    fs_mp.mkdir(parents=True, exist_ok=True)
    path = str(entry.get("path") or "")
    hash_preflight = _preflight_hash_before_mount(path) if path else {
        "success": False, "error": "missing path",
    }
    try:
        from tools.ewf import mount_full_image
        result = mount_full_image(path, str(ewf_mp), str(fs_mp))
        if result.get("success"):
            result["mount_point"] = str(fs_mp)
            result["ntfs_mount"] = str(fs_mp)
        result["hash_preflight"] = hash_preflight
        return result
    except Exception as e:
        return {
            "success": False,
            "error": str(e)[:400],
            "hash_preflight": hash_preflight,
        }


def find_export_for_source(
    case_dir: str | os.PathLike,
    source: str | None,
) -> dict[str, Any] | None:
    """Return an existing export_raw mount-plan entry for ``source``, if any."""
    if not source:
        return None
    plan = load_mount_plan(case_dir)
    src_norm = os.path.abspath(os.path.expanduser(str(source)))
    for img in plan.get("images") or []:
        if img.get("origin") != "export_raw":
            continue
        s = str(img.get("source") or "")
        if not s:
            continue
        try:
            s_abs = os.path.abspath(os.path.expanduser(s))
        except Exception:
            s_abs = s
        if s_abs == src_norm or os.path.basename(s) == os.path.basename(src_norm):
            path = Path(str(img.get("path") or ""))
            if path.is_file() and path.stat().st_size > 0:
                return img
    return None


def register_exported_image(
    case_dir: str | os.PathLike,
    image_path: str | os.PathLike,
    *,
    source: str | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    """Register an analysis-exported disk image on the access plan.

    ``img.vmdk_export_raw`` writes under ``analysis/``, which evidence-profile
    scans miss. Without this handoff the mount plan stays VMDK→chain and the
    agent improvises losetup. After registration the next recommended tool is
    ``tsk.mmls``.
    """
    root = Path(case_dir).resolve()
    p = Path(image_path)
    if not p.is_absolute():
        cand = (root / p).resolve()
        if cand.is_file():
            p = cand
        else:
            p = Path(os.path.abspath(os.path.expanduser(str(image_path))))
    entry = _classify_image(p if p.exists() else Path(str(image_path)))
    entry["path"] = str(p)
    entry["origin"] = "export_raw"
    if source:
        entry["source"] = str(source)
    # Exported raw must open via TSK — never loop/FUSE as next step.
    if entry.get("image_type") in (None, "unknown"):
        entry["image_type"] = "raw_or_container"
    entry["recommended_tool"] = "tsk.mmls"
    entry["action"] = "plan_only"
    entry["access_gated"] = True
    entry["media_role"] = "disk"
    # The Security log's place depends on the Windows generation, which the
    # listing will show; the order names both layouts (core.eventlog_layout).
    from core.eventlog_layout import LAYOUTS, locations
    entry["reason"] = (
        "exported raw — next: tsk.mmls → tsk.fls → the Security event log "
        f"({locations()}; tsk.icat + "
        f"{' or '.join(l.parsers[0] for l in LAYOUTS)}) before signature "
        "hunting; avoid xmount/losetup as Triage default"
    )
    entry["next_work_order"] = [
        "tsk.mmls",
        "tsk.fls",
        f"locate the Security event log ({locations()})",
        "tsk.icat",
        " or ".join(l.parsers[0] for l in LAYOUTS),
    ]
    entry["status"] = "exported"

    plan = load_mount_plan(root)
    images = list(plan.get("images") or [])
    key = str(p)
    replaced = False
    for i, old in enumerate(images):
        if str(old.get("path") or "") == key:
            images[i] = {**old, **entry}
            replaced = True
            break
    if not replaced:
        images.append(entry)
    plan["images"] = images
    plan["case_id"] = root.name
    plan["note"] = (
        "Auto-mount only for unambiguous E01/Ex01 under case/mnt/. "
        "Exported analysis raws are registered for tsk.mmls open."
    )
    if persist:
        save_mount_plan(root, plan)
    return plan


def _image_key_path(image_path: str | os.PathLike) -> str:
    return os.path.realpath(os.path.expanduser(str(image_path)))


def note_volume_offset(case_dir: str | os.PathLike, image_path: str | os.PathLike,
                       offset_sectors: int) -> bool:
    """Remember the partition offset at which a filesystem tool succeeded on
    an image, so later calls can default to it instead of re-deriving it."""
    try:
        offset = int(offset_sectors)
    except (TypeError, ValueError):
        return False
    root = Path(case_dir).resolve()
    plan = load_mount_plan(root)
    offsets = dict(plan.get("volume_offsets") or {})
    key = _image_key_path(image_path)
    if offsets.get(key) == offset:
        return False
    offsets[key] = offset
    plan["volume_offsets"] = offsets
    save_mount_plan(root, plan)
    return True


def volume_offset(case_dir: str | os.PathLike | None, image_path: str | os.PathLike) -> Optional[int]:
    """The remembered partition offset for an image, or None."""
    if not case_dir:
        return None
    try:
        plan = load_mount_plan(Path(case_dir).resolve())
    except Exception:  # noqa: BLE001
        return None
    val = (plan.get("volume_offsets") or {}).get(_image_key_path(image_path))
    return int(val) if val is not None else None
