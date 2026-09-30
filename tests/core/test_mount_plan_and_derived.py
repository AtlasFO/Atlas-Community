"""Mount plan + derived revisit (case-driven V1)."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from core.mount_plan import (
    build_mount_plan,
    _classify_image,
    plane_a_auto_mount_allowed,
)
from core.derived_revisit import derive_revisit_tasks
from core.evidence_links import save_evidence_links
from core.investigation_tasks import reconcile_case_md, add_derived_task, load_tasks
from core.incremental import plane_a_scan


def test_classify_e01_auto_vs_vmdk_plan_only(tmp_path: Path):
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"x")
    vmdk = tmp_path / "disk.vmdk"
    vmdk.write_bytes(b"y")
    a = _classify_image(e01)
    assert a["action"] == "auto_mount"
    assert a["image_type"] == "ewf"
    b = _classify_image(vmdk)
    assert b["action"] == "plan_only"
    assert b["image_type"] == "vmdk"


def test_classify_srudb_skipped_not_disk(tmp_path: Path):
    sru = tmp_path / "SRUDB.dat"
    sru.write_bytes(b"not-a-disk")
    c = _classify_image(sru)
    assert c["action"] == "skip"
    assert c.get("image_type") == "non_disk_artifact"
    assert c.get("access_gated") is False


def test_ewf_continuation_segments_ride_with_their_first_segment(tmp_path: Path):
    for name in ("disk.E02", "disk.E04", "disk.Ex03"):
        seg = tmp_path / name
        seg.write_bytes(b"EVF")
        c = _classify_image(seg)
        assert c["action"] == "skip", name
        assert c["image_type"] == "ewf_segment"
        assert c["access_gated"] is False
    first = tmp_path / "disk.E01"
    first.write_bytes(b"EVF")
    assert _classify_image(first)["action"] == "auto_mount"


def test_plane_a_auto_mount_policy_off(monkeypatch):
    monkeypatch.setenv("ATLAS_PLANE_A_AUTO_MOUNT", "off")
    ok, reason = plane_a_auto_mount_allowed()
    assert ok is False
    assert "off" in reason


def test_auto_mount_skipped_when_sudo_unavailable(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ATLAS_PLANE_A_AUTO_MOUNT", "auto")
    monkeypatch.delenv("ATLAS_SKIP_SUDO_CHECK", raising=False)
    case = tmp_path / "case"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    (ev / "host.E01").write_bytes(b"fake-ewf")
    from core.evidence_profile import ensure_evidence_profile
    ensure_evidence_profile(case, refresh=True)
    with patch(
        "core.mount_plan.plane_a_auto_mount_allowed",
        return_value=(False, "sudo_unavailable:test"),
    ), patch("core.mount_plan._auto_mount_e01") as mount_fn:
        plan = build_mount_plan(case, persist=True, auto_mount=True)
    mount_fn.assert_not_called()
    assert any("auto_mount_skipped" in n for n in (plan.get("soft_notes") or []))
    assert plan.get("auto_mounted") == []


def test_non_ntfs_soft_plan_only(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ATLAS_PLANE_A_AUTO_MOUNT", "force")
    case = tmp_path / "case"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    (ev / "linux.E01").write_bytes(b"fake-ewf")
    from core.evidence_profile import ensure_evidence_profile
    ensure_evidence_profile(case, refresh=True)

    def _fake_mount(case_dir, entry):
        return {
            "success": False,
            "gate": "non_ntfs",
            "stderr": "Could not detect NTFS partition from mmls output.",
            "hash_preflight": {"success": True, "full_hash": False},
        }

    with patch("core.mount_plan._auto_mount_e01", side_effect=_fake_mount):
        plan = build_mount_plan(case, persist=True, auto_mount=True)
    img = next(i for i in plan["images"] if i.get("image_type") == "ewf")
    assert img["status"] == "plan_only"
    assert img["action"] == "plan_only"
    assert plan.get("errors") == []
    assert any("non_ntfs" in n for n in (plan.get("soft_notes") or []))


def test_hash_preflight_before_mount(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ATLAS_PLANE_A_AUTO_MOUNT", "force")
    case = tmp_path / "case"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    e01 = ev / "host.E01"
    e01.write_bytes(b"fake-ewf-bytes")
    from core.evidence_profile import ensure_evidence_profile
    ensure_evidence_profile(case, refresh=True)
    calls: list[str] = []

    def _hash(path):
        calls.append(f"hash:{path}")
        return {"success": True, "full_hash": False, "deferred": True,
                "sampled_sha256": "abc"}

    def _mount(image, ewf_mp, fs_mp):
        calls.append("mount")
        return {"success": True, "ntfs_offset_bytes": 0}

    with patch("tools.hashing.verify_evidence_hash", side_effect=_hash), \
         patch("tools.ewf.mount_full_image", side_effect=_mount), \
         patch("core.mount_plan._path_is_mounted", return_value=False):
        plan = build_mount_plan(case, persist=True, auto_mount=True)
    assert calls[0].startswith("hash:")
    assert "mount" in calls
    img = next(i for i in plan["images"] if i.get("basename") == "host.E01")
    assert img.get("hash_preflight", {}).get("success") is True


def test_build_mount_plan_without_auto(tmp_path: Path):
    case = tmp_path / "case"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    (ev / "host.E01").write_bytes(b"fake-ewf")
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Investigate host\n",
        encoding="utf-8",
    )
    # Build profile via plane A or ensure_evidence_profile
    from core.evidence_profile import ensure_evidence_profile
    ensure_evidence_profile(case, refresh=True)
    plan = build_mount_plan(case, persist=True, auto_mount=False)
    assert plan["images"]
    assert any(i.get("image_type") == "ewf" for i in plan["images"])
    assert (case / ".atlas" / "mount_plan.json").is_file()
    # auto_mount=False → no mount attempts
    assert plan.get("auto_mounted") == []


def _case_with_hosts(tmp_path: Path, labels: list[str]) -> Path:
    """A case whose evidence links name ``labels`` as its hosts."""
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Determine what the host name was\n",
        encoding="utf-8",
    )
    reconcile_case_md(case, persist=True)
    save_evidence_links(case, {"links": [
        {"label": h, "path": f"evidence/{h.lower()}.E01", "kind": "disk"}
        for h in labels
    ]})
    return case


def test_derived_revisit_crosses_the_hosts_the_case_knows(tmp_path: Path):
    case = _case_with_hosts(tmp_path, ["WS-ALPHA", "WS-BRAVO"])
    out = derive_revisit_tasks(
        case,
        {"affected_claims": [
            {"id": "c-1", "statement": "Staging tools found on WS-ALPHA"},
        ]},
        persist=True,
    )
    assert out["success"]
    texts = [t["text"] for t in load_tasks(case)["tasks"]]
    derived = [t for t in texts if t.startswith("[derived]")]
    # The other host is raised, the one the claim already names is not.
    # Match the target, not the statement the task quotes back.
    targets = {t.split("Re-check ", 1)[1].split(" for ", 1)[0] for t in derived}
    assert targets == {"WS-BRAVO"}
    # Explicit add_derived still works.
    d = add_derived_task(
        case,
        "[derived] Re-check WS-ALPHA for staging indicators related to: test",
        related_claim_ids=["c-1"],
    )
    assert d["created"] is True


def test_derived_revisit_reads_no_host_out_of_prose_or_a_file_name(tmp_path: Path):
    """"the host name" is not a host, and an evidence basename is not one."""
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    for name in ("alpha.log", "alpha2", "alpha3.log"):
        (case / "evidence" / name).write_bytes(b"x")
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Recover the host name from the image\n",
        encoding="utf-8",
    )
    reconcile_case_md(case, persist=True)
    save_evidence_links(case, {"links": [
        {"label": "WS-ALPHA", "path": "evidence/alpha.log", "kind": "log"},
    ]})
    out = derive_revisit_tasks(
        case,
        {"affected_claims": [
            {"id": "c-1", "statement": "Contraband recovered from the image"},
        ]},
        persist=True,
    )
    assert out["success"]
    assert out["created"] == []
    assert out["note"] == "case knows fewer than two hosts"
    assert not [t for t in load_tasks(case)["tasks"]
                if t["text"].startswith("[derived]")]


def test_derived_revisit_skips_a_claim_that_says_nothing(tmp_path: Path):
    case = _case_with_hosts(tmp_path, ["WS-ALPHA", "WS-BRAVO"])
    out = derive_revisit_tasks(
        case,
        {"affected_claims": [{"id": "c-1", "statement": "", "host": ""}]},
        persist=True,
    )
    assert out["created"] == []


def test_plane_a_writes_mount_plan_key(tmp_path: Path):
    case = tmp_path / "case"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    (ev / "a.txt").write_bytes(b"x")
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Determine compromise\n",
        encoding="utf-8",
    )
    r = plane_a_scan(case, persist=True)
    assert r["success"]
    tr = r.get("task_reconcile") or {}
    assert "mount_plan" in tr or "mount_plan_error" in tr


def test_hash_preflight_carries_the_images_acquisition_digest(monkeypatch):
    """The mount plan records the digest the image stores over the media and
    whether the data still hashes to it, when the hash tool read it."""
    import tools.hashing as hashing
    from core.mount_plan import _preflight_hash_before_mount
    monkeypatch.setattr(hashing, "verify_evidence_hash", lambda p: {
        "success": True, "full_hash": True, "md5": "a" * 32,
        "acquisition_hashes": {"md5": "b" * 32}, "acquisition_verified": True,
        "media_size_bytes": 4871301120})
    out = _preflight_hash_before_mount("/case/evidence/disk.E01")
    assert out["acquisition_hashes"] == {"md5": "b" * 32}
    assert out["acquisition_verified"] is True and out["media_size_bytes"] == 4871301120
    monkeypatch.setattr(hashing, "verify_evidence_hash", lambda p: {"success": True, "md5": "a" * 32})
    assert "acquisition_hashes" not in _preflight_hash_before_mount("/case/evidence/disk.raw")


def test_the_raw_device_of_an_ewf_image_is_found_from_the_plan_or_the_convention(tmp_path):
    """TSK reads an Expert Witness image through the device ewfmount exposes:
    the one the plan recorded, else the auto-mount convention path, and
    nothing when neither is exposed."""
    from core.mount_plan import ewf_device_for, is_ewf_image, save_mount_plan
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    image = case / "evidence" / "host#1.E01"
    image.parent.mkdir(); image.write_bytes(b"EVF")
    assert is_ewf_image(image) and not is_ewf_image(case / "evidence" / "disk.dd")
    assert ewf_device_for(case, image) is None
    conv = case / "mnt" / "host_1" / "ewf" / "ewf1"
    conv.parent.mkdir(parents=True); conv.write_bytes(b"\x00" * 512)
    assert ewf_device_for(case, image) == str(conv)
    other = case / "mnt" / "manual" / "ewf1"
    other.parent.mkdir(parents=True); other.write_bytes(b"\x00" * 512)
    save_mount_plan(case, {"images": [{"path": str(image), "mount_result": {"ewf_device": str(other)}}]})
    assert ewf_device_for(case, image) == str(other)
    assert ewf_device_for(None, image) is None


def _plan_case(tmp_path: Path, *images: str) -> Path:
    case = tmp_path / "case"
    for rel in images:
        f = case / "evidence" / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"fake-ewf")
    from core.evidence_profile import ensure_evidence_profile
    ensure_evidence_profile(case, refresh=True)
    return case


def test_a_plan_that_says_mounted_is_mounted_again_when_the_mount_is_gone(tmp_path: Path, monkeypatch):
    """After a reboot or an unmount the prior plan still says mounted; the
    rebuild checks the mount table and mounts the image again."""
    from core.mount_plan import save_mount_plan
    monkeypatch.setenv("ATLAS_PLANE_A_AUTO_MOUNT", "force")
    case = _plan_case(tmp_path, "host.E01")
    image = case / "evidence" / "host.E01"
    fs = case / "mnt" / "host" / "fs"
    save_mount_plan(case, {"images": [{
        "path": str(image), "basename": "host.E01", "stem": "host", "status": "mounted",
        "action": "auto_mount", "access_gated": True, "image_type": "ewf",
        "mount_result": {"success": True, "mount_point": str(fs)}}]})
    mounts: list[str] = []

    def _mount(case_dir, entry):
        mounts.append(entry.get("mount_stem"))
        return {"success": True, "mount_point": str(fs)}

    with patch("core.mount_plan._path_is_mounted", return_value=False), \
         patch("core.mount_plan._auto_mount_e01", side_effect=_mount):
        plan = build_mount_plan(case, persist=True, auto_mount=True)
    assert mounts == ["host"]
    assert any(n == "remount:host.E01" for n in plan["soft_notes"])
    img = next(i for i in plan["images"] if i.get("basename") == "host.E01")
    assert img["status"] == "mounted"

    # The same plan with the mount live gets no call.
    mounts.clear()
    with patch("core.mount_plan._path_is_mounted", return_value=True), \
         patch("core.mount_plan._auto_mount_e01", side_effect=_mount):
        build_mount_plan(case, persist=True, auto_mount=True)
    assert mounts == []


def test_a_stale_mount_is_no_longer_claimed_with_auto_mount_off(tmp_path: Path):
    from core.mount_plan import save_mount_plan
    case = _plan_case(tmp_path, "host.E01")
    save_mount_plan(case, {"images": [{
        "path": str(case / "evidence" / "host.E01"), "basename": "host.E01", "stem": "host",
        "status": "mounted", "action": "auto_mount", "access_gated": True,
        "mount_result": {"success": True, "mount_point": str(case / "mnt" / "host" / "fs")}}]})
    with patch("core.mount_plan._path_is_mounted", return_value=False):
        plan = build_mount_plan(case, persist=True, auto_mount=False)
    img = next(i for i in plan["images"] if i.get("basename") == "host.E01")
    assert img.get("status") != "mounted"
    assert img["mount_result"]["stale"] is True


def test_images_of_one_name_get_folders_of_their_own(tmp_path: Path, monkeypatch):
    from core.mount_plan import ewf_device_for, mount_dir_for
    monkeypatch.setenv("ATLAS_PLANE_A_AUTO_MOUNT", "force")
    case = _plan_case(tmp_path, "a/disk.E01", "b/disk.E01", "c/laptop.E01")
    folders: dict[str, str] = {}

    def _mount(case_dir, entry):
        folders[entry["path"]] = entry["mount_stem"]
        return {"success": True,
                "mount_point": str(case_dir / "mnt" / entry["mount_stem"] / "fs"),
                "ewf_device": str(case_dir / "mnt" / entry["mount_stem"] / "ewf" / "ewf1")}

    with patch("core.mount_plan._path_is_mounted", return_value=False), \
         patch("core.mount_plan._auto_mount_e01", side_effect=_mount):
        plan = build_mount_plan(case, persist=True, auto_mount=True)
    a = str(case / "evidence" / "a" / "disk.E01")
    b = str(case / "evidence" / "b" / "disk.E01")
    assert folders[a] != folders[b]
    assert folders[a].startswith("disk-") and folders[b].startswith("disk-")
    assert folders[str(case / "evidence" / "c" / "laptop.E01")] == "laptop"

    # A rebuild keeps every folder; the live mounts are reused, not remounted.
    with patch("core.mount_plan._path_is_mounted", return_value=True), \
         patch("core.mount_plan._auto_mount_e01") as again:
        plan2 = build_mount_plan(case, persist=True, auto_mount=True)
    again.assert_not_called()
    assert {i["path"]: i["mount_stem"] for i in plan2["images"]} == folders

    # The same image named by an equivalent path spelling gets the same folder.
    from core.mount_plan import _assign_mount_stems
    twins = [{"path": a, "stem": "disk"},
             {"path": str(case / "evidence" / "b" / ".." / "b" / "disk.E01"), "stem": "disk"}]
    _assign_mount_stems(case, twins)
    assert twins[1]["mount_stem"] == folders[b]

    entry_b = next(i for i in plan2["images"] if i["path"] == b)
    assert mount_dir_for(case, b, entry_b) == str(case / "mnt" / folders[b])
    dev_b = case / "mnt" / folders[b] / "ewf" / "ewf1"
    dev_b.parent.mkdir(parents=True, exist_ok=True)
    dev_b.write_bytes(b"\x00" * 512)
    assert ewf_device_for(case, b) == str(dev_b)
    assert ewf_device_for(case, a) is None


def test_a_folder_shared_through_a_reuse_record_goes_back_to_the_image_that_mounted_it(tmp_path: Path):
    from core.mount_plan import _assign_mount_stems
    case = tmp_path / "case"
    fs = str(case / "mnt" / "disk" / "fs")
    images = [
        {"path": str(case / "evidence" / "b" / "disk.E01"), "stem": "disk",
         "mount_result": {"success": True, "reused": True, "mount_point": fs}},
        {"path": str(case / "evidence" / "a" / "disk.E01"), "stem": "disk",
         "mount_result": {"success": True, "mount_point": fs}},
    ]
    _assign_mount_stems(case, images)
    assert images[1]["mount_stem"] == "disk"
    assert images[0]["mount_stem"].startswith("disk-")
