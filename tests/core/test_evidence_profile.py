"""Tests for evidence profile + evidence-compat gate (facts, not playbooks)."""
from __future__ import annotations

from pathlib import Path

import pytest


def _case_with(tmp_path: Path, files: dict[str, bytes]) -> Path:
    case = tmp_path / "CaseX"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    (case / "analysis").mkdir()
    for rel, data in files.items():
        path = ev / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return case


class TestClassify:
    def test_tabular_extensions(self):
        from core.evidence_profile import classify_path
        assert classify_path(Path("a.csv")) == "tabular"
        assert classify_path(Path("b.XLSX")) == "tabular"

    def test_disk_and_memory(self):
        from core.evidence_profile import classify_path
        assert classify_path(Path("disk.E01")) == "disk"
        assert classify_path(Path("split.E02")) == "disk"
        assert classify_path(Path("ram.vmem")) == "memory"

    def test_evtx_and_pcap(self):
        from core.evidence_profile import classify_path
        assert classify_path(Path("Security.evtx")) == "windows_eventlog"
        assert classify_path(Path("cap.pcapng")) == "pcap"


class TestProfileBuild:
    def test_collection_like_package(self, tmp_path):
        from core.evidence_profile import build_evidence_profile, ensure_evidence_profile
        case = _case_with(tmp_path, {
            "vpn_logons.csv": b"a,b\n1,2\n",
            "logon_export.xlsx": b"PK\x03\x04fake",
        })
        profile = build_evidence_profile(case)
        assert "tabular" in profile["present_classes"]
        assert "disk" in profile["absent_classes"]
        assert "memory" in profile["absent_classes"]
        assert "windows_eventlog" in profile["absent_classes"]
        assert profile["file_count"] == 2

        saved = ensure_evidence_profile(case)
        assert (case / ".atlas" / "evidence_profile.json").is_file()
        assert saved["present_classes"] == profile["present_classes"]

    def test_prompt_is_facts_not_playbook(self, tmp_path):
        from core.evidence_profile import (
            build_evidence_profile,
            format_profile_for_prompt,
        )
        case = _case_with(tmp_path, {"a.csv": b"x\n"})
        text = format_profile_for_prompt(build_evidence_profile(case))
        assert "factual inventory" in text.lower()
        assert "not a playbook" in text.lower()
        assert "tabular" in text
        # No hard-coded investigation step for CSV cases, and no identifier
        # carried over from any case: the text names no account, host or
        # address, and no label shaped like one (letters then digits).
        import re
        from core.entities import extract
        assert not {e for e in extract(text)
                    if e.split(":", 1)[0] in ("account", "host", "ip", "email")}
        assert not re.findall(r"\b[A-Za-z][A-Za-z_-]*\d+\b", text)
        assert "always table_grep" not in text.lower()


    def test_ensure_refresh_picks_up_new_evtx(self, tmp_path):
        from core.evidence_profile import ensure_evidence_profile

        case = _case_with(tmp_path, {"logons.csv": b"a,b\n"})
        first = ensure_evidence_profile(case)
        assert "windows_eventlog" not in first["present_classes"]
        # Simulate KAPE/EVTX intake after the cached profile was written
        (case / "evidence" / "Security.evtx").write_bytes(b"ElfFile\x00")
        stale = ensure_evidence_profile(case)  # refresh=False default
        assert "windows_eventlog" not in stale["present_classes"]
        fresh = ensure_evidence_profile(case, refresh=True)
        assert "windows_eventlog" in fresh["present_classes"]
        assert fresh["file_count"] >= 2


class TestCompatGate:
    def test_blocks_ewf_without_disk(self, tmp_path):
        from core.evidence_profile import build_evidence_profile
        from tools.evidence_compat import check_tool_against_profile, tool_compatible

        case = _case_with(tmp_path, {"logons.csv": b"u,p\n"})
        profile = build_evidence_profile(case)
        ok, reason = tool_compatible("ewf_ewf_mount", profile["present_classes"])
        assert not ok
        assert "evidence-compat" in reason
        refusal = check_tool_against_profile("ewf_ewf_mount", profile)
        assert refusal and refusal["gate"] == "evidence_compat"

    def test_allows_table_with_tabular(self, tmp_path):
        from core.evidence_profile import build_evidence_profile
        from tools.evidence_compat import tool_compatible

        case = _case_with(tmp_path, {"logons.csv": b"u,p\n"})
        profile = build_evidence_profile(case)
        ok, _ = tool_compatible("table_table_grep", profile["present_classes"])
        assert ok

    def test_blocks_evtx_without_logs_or_disk(self, tmp_path):
        from core.evidence_profile import build_evidence_profile
        from tools.evidence_compat import tool_compatible

        case = _case_with(tmp_path, {"logons.csv": b"u,p\n"})
        profile = build_evidence_profile(case)
        ok, _ = tool_compatible("ez_ez_evtxecmd", profile["present_classes"])
        assert not ok

    def test_allows_evtx_when_disk_present(self, tmp_path):
        from core.evidence_profile import build_evidence_profile
        from tools.evidence_compat import tool_compatible

        case = _case_with(tmp_path, {"host.E01": b"EVF\x09\x0d\x0d\x0a"})
        profile = build_evidence_profile(case)
        ok, _ = tool_compatible("ez_ez_evtxecmd", profile["present_classes"])
        assert ok

    def test_allows_path_parsers_when_file_present(self, tmp_path):
        from core.evidence_profile import build_evidence_profile
        from tools.evidence_compat import tool_compatible

        case = _case_with(tmp_path, {"SYSTEM": b"regf" + b"\x00" * 32})
        profile = build_evidence_profile(case)
        present = set(profile["present_classes"]) | {"file"}
        # Structural rule: path parsers (any ez_*) accept file|disk
        for tool in ("ez_ez_recmd_hive", "ez_ez_mftecmd", "ez_ez_pecmd"):
            ok, reason = tool_compatible(tool, present)
            assert ok, f"{tool}: {reason}"

    def test_blocks_path_parsers_on_tabular_only(self, tmp_path):
        from core.evidence_profile import build_evidence_profile
        from tools.evidence_compat import tool_compatible

        case = _case_with(tmp_path, {"logons.csv": b"u,p\n"})
        profile = build_evidence_profile(case)
        ok, reason = tool_compatible(
            "ez_ez_recmd_hive", profile["present_classes"],
        )
        assert not ok
        assert "evidence-compat" in reason

    def test_file_class_suggests_ez_not_ewf(self, tmp_path):
        from core.evidence_profile import build_evidence_profile
        from tools.evidence_compat import suggested_core_namespaces

        case = _case_with(tmp_path, {"SYSTEM": b"regf" + b"\x00" * 32})
        ns = suggested_core_namespaces(build_evidence_profile(case))
        assert "ez" in ns
        assert "ewf" not in ns

    def test_core_namespaces_skip_ewf_on_tabular(self, tmp_path):
        from core.evidence_profile import build_evidence_profile
        from tools.evidence_compat import suggested_core_namespaces

        case = _case_with(tmp_path, {"a.csv": b"x\n"})
        ns = suggested_core_namespaces(build_evidence_profile(case))
        assert "table" in ns
        assert "ewf" not in ns
        assert "vol" not in ns
        assert "misc" in ns and "reason" in ns

    def test_core_namespaces_include_ewf_when_disk(self, tmp_path):
        from core.evidence_profile import build_evidence_profile
        from tools.evidence_compat import suggested_core_namespaces

        case = _case_with(tmp_path, {"disk.E01": b"EVF"})
        ns = suggested_core_namespaces(build_evidence_profile(case))
        assert "ewf" in ns


class TestSystemPromptInjection:
    def test_build_system_prompt_includes_profile(self, tmp_path):
        from agent.prompts import build_system_prompt

        case = _case_with(tmp_path, {"vpn.csv": b"a,b\n"})
        (case / "CASE.md").write_text("# Case\n", encoding="utf-8")
        text = build_system_prompt(case)
        assert "EVIDENCE PROFILE" in text
        assert "tabular" in text


def test_high_value_tables_leave_out_plain_text_and_deep_files():
    from core.evidence_profile import high_value_tabular_index
    profile = {"files": [
        {"path": "evidence/README.txt", "class": "file"},
        {"path": "evidence/MD5SUMS.txt", "class": "file"},
        {"path": "evidence/vpn_logons.csv", "class": "tabular"},
        {"path": "evidence/exports/edr_events.csv", "class": "tabular"},
        {"path": "evidence/a/b/deep.csv", "class": "tabular"},
        {"path": "evidence/parsed/WS01/MFTECmd/WS01_mft.csv", "class": "tabular"},
    ]}
    picked = high_value_tabular_index(profile)
    assert "evidence/README.txt" not in picked and "evidence/MD5SUMS.txt" not in picked
    assert "evidence/vpn_logons.csv" in picked
    assert "evidence/exports/edr_events.csv" in picked
    assert "evidence/a/b/deep.csv" not in picked
    assert picked[0] == "evidence/parsed/WS01/MFTECmd/WS01_mft.csv"
