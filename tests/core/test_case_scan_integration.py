"""Regressions of the evidence scan on realistically shaped cases.

Every bug below passed the module's own unit tests. They share a cause worth
naming: the fixtures were too small and too clean to expose them — one
symlink, a host's worth of mostly empty event-log channels, or Atlas's own
output sitting in the case directory is all it takes.
"""
from __future__ import annotations

import json
import os

from core import artifact_value as av
from core import ioc_pivots as ip
from core import source_sets as ss
from core.evidence_catalog import iter_case_files

EMPTY_EVTX = 69632


def _linked_case(tmp_path):
    """A case whose evidence is symlinked in — how real evidence arrives.

    Nobody copies a multi-gigabyte KAPE export or a mounted image into the
    case dir.
    """
    store = tmp_path / "store" / "KAPE" / "Windows" / "System32" / "winevt"
    store.mkdir(parents=True)
    (store / "Security.evtx").write_bytes(b"x" * 20_971_520)
    (store / "Setup.evtx").write_bytes(b"x" * EMPTY_EVTX)     # empty channel
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / ".atlas").mkdir()
    (case / "evidence" / "KAPE").symlink_to(tmp_path / "store" / "KAPE")
    return case


class TestOpenedImageMountsAreNotCaseFiles:
    """A disk image mounted under analysis/ is examined through the disk
    tools; walking it as case files made every per-turn scan take minutes."""

    def _case_with_mounts(self, tmp_path, monkeypatch):
        case = tmp_path / "case"
        (case / "evidence" / "export").mkdir(parents=True)
        (case / "evidence" / "export" / "Security.evtx").write_bytes(b"x" * 100)
        (case / "analysis" / "dc01_fs" / "Windows").mkdir(parents=True)
        (case / "analysis" / "dc01_fs" / "Windows" / "notepad.exe").write_bytes(b"MZ")
        (case / "analysis" / "parsed.csv").write_text("a,b\n" * 40)
        mounts = {str(case / "analysis" / "dc01_fs"), str(case / "evidence" / "export")}
        monkeypatch.setattr("core.evidence_catalog.os.path.ismount",
                            lambda p: str(p) in mounts)
        return case

    def test_the_shared_scanner_skips_a_mount_under_analysis(self, tmp_path, monkeypatch):
        case = self._case_with_mounts(tmp_path, monkeypatch)
        names = {os.path.basename(rel) for rel, _ in iter_case_files(case)}
        assert "parsed.csv" in names
        assert "notepad.exe" not in names
        assert "Security.evtx" in names  # a mount under evidence/ is attached evidence

    def test_the_output_walk_and_its_consumers_skip_the_mount(self, tmp_path, monkeypatch):
        case = self._case_with_mounts(tmp_path, monkeypatch)
        from core.coverage import find_related_artifacts
        from core.coverage_ledger import exploration_fingerprint
        from core.evidence_catalog import iter_output_files
        assert [p.name for p in iter_output_files(case / "analysis")] == ["parsed.csv"]
        assert [os.path.basename(p) for p in find_related_artifacts(str(case))] == ["parsed.csv"]
        assert "notepad" not in repr(exploration_fingerprint(case))


class TestSymlinkedEvidenceIsVisible:
    """Path.rglob refuses to descend a symlinked directory, so every check
    built on it reported an empty case — silently."""

    def test_the_shared_scanner_follows_symlinks(self, tmp_path):
        case = _linked_case(tmp_path)
        names = {os.path.basename(rel) for rel, _ in iter_case_files(case)}
        assert "Security.evtx" in names

    def test_evidence_sources_sees_symlinked_evidence(self, tmp_path):
        case = _linked_case(tmp_path)
        assert any(s.endswith("Security.evtx")
                   for s in ip.evidence_sources(case))

    def test_known_artifacts_sees_symlinked_evidence(self, tmp_path):
        case = _linked_case(tmp_path)
        assert "security.evtx" in av.known_artifacts(case)

    def test_the_high_value_obligation_still_fires(self, tmp_path):
        """The protection this was all built for must survive a symlink."""
        case = _linked_case(tmp_path)
        (case / "analysis" / "CASE_trace.json").write_text("[]", encoding="utf-8")
        assert any(a["name"] == "Security.evtx"
                   for a in av.unexamined_high_value(case))

    def test_a_symlink_cycle_terminates(self, tmp_path):
        """os.walk(followlinks=True) loops forever on a cycle; a scan that
        hangs is indistinguishable from a wedged tool call."""
        case = tmp_path / "case"
        (case / "evidence" / "deep").mkdir(parents=True)
        (case / "evidence" / "deep" / "loop").symlink_to(case / "evidence")
        (case / "evidence" / "a.log").write_text("x", encoding="utf-8")
        names = [rel for rel, _ in iter_case_files(case)]   # must return
        assert any(n.endswith("a.log") for n in names)


class TestEventLogObligationIsSatisfiable:
    """A Windows host ships well over a hundred channels, most of them empty.
    Requiring all of them makes `complete` unreachable — the always-complete
    bug inverted."""

    def _case(self, tmp_path, *, analysed=()):
        case = tmp_path / "case"
        logs = case / "evidence" / "winevt"
        logs.mkdir(parents=True)
        (case / ".atlas").mkdir()
        (case / "analysis").mkdir()
        (logs / "Security.evtx").write_bytes(b"x" * 20_971_520)
        for i in range(40):      # noise channels, all empty
            (logs / f"Microsoft-Windows-Noise%4Op{i}.evtx").write_bytes(
                b"x" * EMPTY_EVTX)
        (case / "analysis" / "CASE_trace.json").write_text(
            json.dumps([{"type": "tool_call", "cmd": f"evtxecmd -f {n}"}
                        for n in analysed]), encoding="utf-8")
        return case

    def test_empty_channels_are_not_owed(self, tmp_path):
        from core.investigation_obligations import list_obligations
        case = self._case(tmp_path, analysed=["Security.evtx"])
        ob = next(o for o in list_obligations(case)
                  if o["id"] == "event_logs_analysed")
        assert ob["met"], ob["detail"]

    def test_the_log_that_matters_is_still_owed(self, tmp_path):
        from core.investigation_obligations import list_obligations
        case = self._case(tmp_path, analysed=[])
        ob = next(o for o in list_obligations(case)
                  if o["id"] == "event_logs_analysed")
        assert not ob["met"]
        assert "Security.evtx" in ob["detail"]


class TestPivotTargetQuality:
    def _case(self, tmp_path):
        case = tmp_path / "case"
        (case / "evidence" / "winevt").mkdir(parents=True)
        (case / "analysis").mkdir()
        (case / ".atlas").mkdir()
        for name in ("Security.evtx", "Application.evtx",
                     "Microsoft-Windows-PowerShell%4Operational.evtx"):
            (case / "evidence" / "winevt" / name).write_bytes(b"x" * 5_000_000)
        # Atlas's own run output, sitting in the case dir
        (case / "analysis" / "CASE_trace.json").write_text(
            '[{"type":"tool_call","cmd":"note 203.0.113.44"}]', encoding="utf-8")
        (case / "analysis" / "agent_transcript_x.jsonl").write_text(
            '{"content":"203.0.113.44"}\n', encoding="utf-8")
        (case / ".atlas" / "claim_graph.json").write_text(json.dumps({
            "nodes": {"C1": {"id": "C1", "kind": "claim", "status": "new",
                             "statement": "Beacon to 203.0.113.44 observed."}},
            "edges": []}), encoding="utf-8")
        return case

    def test_atlas_own_output_is_never_a_pivot_target(self, tmp_path):
        """An indicator is in the trace because the run wrote it there —
        'search the transcript for it' is circular, and observe_search would
        close the pivot on evidence that was never examined."""
        case = self._case(tmp_path)
        ip.refresh_pivots(case)
        targets = [t for p in ip.open_pivots(case) for t in p["pending"]]
        assert targets
        assert not [t for t in targets
                    if "trace" in t or "transcript" in t or ".atlas" in t]

    def test_targets_are_offered_in_value_order(self, tmp_path):
        """open_pivots used to sort alphabetically, so a display cap showed
        Application.evtx and cut off Security.evtx."""
        case = self._case(tmp_path)
        ip.refresh_pivots(case)
        pending = ip.open_pivots(case)[0]["pending"]
        assert pending[0].endswith("Security.evtx"), pending[:3]
        assert ip.format_pivot_nudge(ip.open_pivots(case)).index(
            "Security.evtx") < 900


class TestSourceSetsOnLinkedEvidence:
    def test_a_rotated_series_behind_a_symlink_is_seen(self, tmp_path):
        store = tmp_path / "store" / "fw"
        store.mkdir(parents=True)
        for d in range(1, 7):
            (store / f"2031-02-{d:02d}.log").write_text("x", encoding="utf-8")
        case = tmp_path / "case"
        (case / "evidence").mkdir(parents=True)
        (case / "analysis").mkdir()
        (case / "evidence" / "fw").symlink_to(store)
        (case / "analysis" / "CASE_trace.json").write_text(
            '[{"type":"tool_call","cmd":"grep x evidence/fw/2031-02-01.log"}]',
            encoding="utf-8")
        partial = ss.partially_examined_series(case)
        assert partial and partial[0]["total"] == 6
        assert partial[0]["examined"] == 1
