"""Run-hardening regression tests (core).

Covers:
  - resolve_case_dir: LLM-supplied case *names* must never fabricate paths
    (a fabricated path fails every task update and leaves the final
    report empty).
  - _hosts_from_text: prose stopwords must not become focus_hosts ("using").
  - _path_capabilities: already-parsed exports must never map to hive tools
    (SECURITY.regripper.txt → misc.regripper_hive static hint).
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch


def _case(tmp_path: Path, name: str = "CaseX") -> Path:
    case = tmp_path / name
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / "evidence").mkdir()
    return case


class TestResolveCaseDir:
    def _with_active(self, active: str | None):
        stub = MagicMock()
        stub.case_dir.return_value = active
        return patch("core.execution_log.log", stub)

    def test_empty_returns_active(self, tmp_path):
        from core.claim_graph import resolve_case_dir
        case = _case(tmp_path)
        with self._with_active(str(case)):
            assert resolve_case_dir(None) == str(case)
            assert resolve_case_dir("") == str(case)

    def test_case_name_maps_to_active(self, tmp_path):
        """A case name passed as case_dir (a name, not a path) maps to the
        active case."""
        from core.claim_graph import resolve_case_dir
        case = _case(tmp_path, "CASE-A")
        with self._with_active(str(case)):
            assert resolve_case_dir("CASE-A") == str(case)

    def test_nonexistent_string_is_rejected_even_with_active_case(self, tmp_path):
        """Silently aliasing an unrecognized name to the active case would
        let a typo write into the wrong case under a false 'success' —
        must refuse instead."""
        from core.claim_graph import resolve_case_dir
        case = _case(tmp_path)
        with self._with_active(str(case)):
            assert resolve_case_dir("does/not/exist") is None

    def test_existing_case_root_wins(self, tmp_path):
        from core.claim_graph import resolve_case_dir
        active = _case(tmp_path, "Active")
        other = _case(tmp_path, "Other")
        with self._with_active(str(active)):
            assert resolve_case_dir(str(other)) == str(other.resolve())

    def test_no_active_rejects_nonexistent(self, tmp_path):
        from core.claim_graph import resolve_case_dir
        with self._with_active(None):
            assert resolve_case_dir("nope/missing") is None

    def test_no_active_accepts_plain_existing_dir(self, tmp_path):
        """Unit tests point loaders at bare tmp dirs — keep that working."""
        from core.claim_graph import resolve_case_dir
        bare = tmp_path / "bare"
        bare.mkdir()
        with self._with_active(None):
            assert resolve_case_dir(str(bare)) == str(bare.resolve())

    def test_update_task_with_case_name_reaches_real_store(self, tmp_path):
        """End-to-end: update_investigation_task called with a case name
        as case_dir."""
        from core.investigation_tasks import (
            _make_task, empty_tasks, load_tasks, save_tasks,
        )
        from tools.misc import update_investigation_task
        case = _case(tmp_path, "CASE-A")
        store = empty_tasks("CASE-A")
        task = _make_task(store, "What happened on the fileserver?")
        store["tasks"].append(task)
        store["next_id"] = 2
        save_tasks(case, store)
        from core.claim_graph import add_claim
        cid = add_claim(case, "The fileserver was encrypted by ransomware.",
                        confidence="LIKELY", enforce_validation=False)["node_id"]
        stub = MagicMock()
        stub.case_dir.return_value = str(case)
        with patch("core.execution_log.log", stub):
            out = update_investigation_task(
                task_id="task-0001", status="answered",
                related_claim_ids=[cid],
                case_dir="CASE-A")
        assert out.get("success"), out
        store = load_tasks(case)
        assert store["tasks"][0]["status"] == "answered"


class TestFocusHostsStopwords:
    def test_prose_after_host_is_not_a_hostname(self):
        from core.investigation_plan import _hosts_from_text
        text = ("Reconstruct the session chain on that host using the "
                "KAPE outputs under evidence/.")
        assert _hosts_from_text(text) == []

    def test_real_hostnames_still_extracted(self):
        from core.investigation_plan import _hosts_from_text
        text = "What happened on host SRV01 and server dc01?"
        assert _hosts_from_text(text) == ["SRV01", "dc01"]


class TestPreparsedExportCapabilities:
    def test_regripper_export_maps_to_table_not_hive(self):
        from core.investigation_orchestrator import _path_capabilities
        caps = _path_capabilities(
            "evidence/parsed/host/RegRipper/SECURITY.regripper.txt")
        assert caps[0] == "tabular_export_analysis"
        assert "windows_registry_identity" not in caps

    def test_plain_txt_export_routes_to_table(self):
        from core.investigation_orchestrator import _path_capabilities
        caps = _path_capabilities("evidence/parsed/host/SYSTEM.txt")
        assert caps[0] == "tabular_export_analysis"
        assert "windows_registry_identity" not in caps

    def test_raw_hive_still_maps_to_registry(self):
        from core.investigation_orchestrator import _path_capabilities
        caps = _path_capabilities(
            "evidence/raw_extract/host/Windows/System32/config/SYSTEM")
        assert "windows_registry_identity" in caps

    def test_csv_export_prefers_table(self):
        from core.investigation_orchestrator import _path_capabilities
        caps = _path_capabilities(
            "evidence/parsed/host/Chainsaw/lateral_movement.csv")
        assert caps[0] == "tabular_export_analysis"
