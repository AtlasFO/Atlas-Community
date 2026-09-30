"""The director is told where the case's images are open and how a path
on them is spelled: the block names the live mount point, the device and
the profile directory names, comes first in the message, and is absent
when no mount is live - a directory the plan created for a mount that is
gone is not a volume."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from core.mount_plan import mounted_volumes, save_mount_plan

_ASSESSMENT = json.dumps({
    "current_phase": "Collect", "phase_rationale": "x", "transition_recommended": False,
    "next_phase": "", "transition_rationale": "", "stack_action": "stay",
    "investigation_focus": "x", "verification_challenges": [], "recommended_actions": [],
    "directives": {"priority_tools": ["tsk.fls"], "skip_tools": [], "focus_pids": [],
                   "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []},
})


def _http_resp(text):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"choices": [{"message": {"content": text}}],
                              "usage": {"prompt_tokens": 1, "completion_tokens": 1}}
    resp.raise_for_status = MagicMock()
    return resp


def _case(tmp_path, *, live=True, profiles=("Mr. Grey", "All Users", "Default User")):
    case = tmp_path / "CASE"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / "evidence").mkdir()
    (case / "evidence" / "notebook.E01").write_bytes(b"EVF" * 8)
    fs = case / "mnt" / "notebook" / "fs"
    (fs / "WINDOWS").mkdir(parents=True)
    for name in profiles:
        (fs / "Documents and Settings" / name).mkdir(parents=True)
    ewf = case / "mnt" / "notebook" / "ewf"
    ewf.mkdir(parents=True)
    (ewf / "ewf1").write_bytes(b"")
    save_mount_plan(case, {"images": [{
        "path": str(case / "evidence" / "notebook.E01"), "basename": "notebook.E01",
        "stem": "notebook", "image_type": "ewf", "status": "mounted",
        "mount_result": {"success": True, "mount_point": str(fs), "ewf_device": str(ewf / "ewf1")}}]})
    return case, fs


def _live(paths):
    return lambda p: str(p).rstrip("/") in {str(x).rstrip("/") for x in paths}


class TestMountedVolumes:
    def test_a_live_mount_is_listed_with_its_profiles(self, tmp_path):
        case, fs = _case(tmp_path)
        with patch("core.mount_plan._path_is_mounted", _live([fs, fs.parent / "ewf"])):
            vols = mounted_volumes(case)
        assert len(vols) == 1
        v = vols[0]
        assert v["rel"] == "mnt/notebook/fs" and v["device_rel"] == "mnt/notebook/ewf/ewf1"
        assert v["profile_root"] == "Documents and Settings"
        assert v["profiles"] == ["All Users", "Default User", "Mr. Grey"]

    def test_a_directory_left_by_a_gone_mount_is_not_a_volume(self, tmp_path):
        case, fs = _case(tmp_path)
        assert fs.is_dir()
        with patch("core.mount_plan._path_is_mounted", lambda p: False):
            assert mounted_volumes(case) == []

    def test_a_device_without_a_filesystem_is_listed_by_device(self, tmp_path):
        case, fs = _case(tmp_path)
        with patch("core.mount_plan._path_is_mounted", _live([fs.parent / "ewf"])):
            vols = mounted_volumes(case)
        assert vols and not vols[0]["rel"] and vols[0]["device_rel"] == "mnt/notebook/ewf/ewf1"

    def test_profile_names_are_bounded_and_the_total_kept(self, tmp_path):
        case, fs = _case(tmp_path, profiles=tuple(f"user{i:02d}" for i in range(30)) + ("x" * 200, "bad\nname"))
        with patch("core.mount_plan._path_is_mounted", _live([fs])):
            v = mounted_volumes(case)[0]
        assert len(v["profiles"]) == 20 and all(len(n) <= 64 for n in v["profiles"])
        assert v["profile_total"] == 32
        assert all("\n" not in n for n in v["profiles"])

    def test_one_line_per_mount_point_when_a_stem_is_reused(self, tmp_path):
        case, fs = _case(tmp_path)
        (case / "evidence" / "other").mkdir()
        (case / "evidence" / "other" / "notebook.E01").write_bytes(b"EVF" * 8)
        from core.mount_plan import load_mount_plan
        plan = load_mount_plan(case)
        first = plan["images"][0]
        plan["images"].append({**first, "path": str(case / "evidence" / "other" / "notebook.E01"),
                               "mount_result": {**first["mount_result"], "reused": True}})
        save_mount_plan(case, plan)
        with patch("core.mount_plan._path_is_mounted", _live([fs, fs.parent / "ewf"])):
            vols = mounted_volumes(case)
        assert len(vols) == 1 and vols[0]["basename"] == "evidence/notebook.E01"


class TestTheDirectorsBlock:
    def _assess(self, case, tmp_path, live):
        from core.execution_log import ExecutionLog
        from tools import dair
        inst = ExecutionLog()
        inst.configure("MV-1", str(case / "analysis" / "trace.json"), save_session=False)
        http_mock = MagicMock(return_value=_http_resp(_ASSESSMENT))
        with patch("core.execution_log.log", inst), \
             patch("core.mount_plan._path_is_mounted", live), \
             patch("httpx.post", http_mock), \
             patch("tools.dair.DAIR_URL", "http://localhost:8000"), \
             patch("tools.dair.DAIR_BACKEND", "openai-compat"), \
             patch.object(dair, "_case_root", lambda: str(case)):
            dair.dair_assess("The notebook image is mounted; root listing shows WINDOWS.",
                             phase_stack="[]", case_context="CASE_QUESTION: who used the notebook? Suspect: Alan Turner")
        entry = [e for e in inst._entries if e["type"] == "dair_call"][-1]
        return entry["inputs"]["user_message"]

    def test_the_block_leads_the_message_and_names_the_profiles(self, tmp_path):
        case, fs = _case(tmp_path)
        msg = self._assess(case, tmp_path, _live([fs, fs.parent / "ewf"]))
        assert msg.startswith("MOUNTED VOLUMES")
        assert "filesystem at mnt/notebook/fs" in msg
        assert "device mnt/notebook/ewf/ewf1" in msg
        assert "Documents and Settings: All Users, Default User, Mr. Grey" in msg
        assert "shown)" not in msg
        assert msg.index("MOUNTED VOLUMES") < msg.index("TOOL RESULTS SUMMARY")

    def test_no_live_mount_means_no_block(self, tmp_path):
        case, fs = _case(tmp_path)
        msg = self._assess(case, tmp_path, lambda p: False)
        assert "MOUNTED VOLUMES" not in msg and msg.startswith("TOOL RESULTS SUMMARY")

    def test_the_system_prompt_states_the_mapping(self):
        from tools.dair import _DAIR_SYS
        assert "MOUNTED VOLUMES block" in _DAIR_SYS
        assert "never a name taken from the brief" in _DAIR_SYS
