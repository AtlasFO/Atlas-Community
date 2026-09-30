"""Report projection — sections from investigation state, not Markdown SoT."""
from __future__ import annotations

from pathlib import Path

from core.claim_graph import add_claim, add_conflict
from core.incremental import plane_a_scan
from core.report_projection import (
    assemble_report,
    bind_claims_to_sections,
    load_manifest,
    mark_stale_sections,
    regenerate_sections,
    render_markdown,
    resolve_section_id,
    section_context,
)


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "reports").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** ProjTest\n", encoding="utf-8")
    (case / "evidence" / "a.txt").write_bytes(b"x")
    return case


def test_plane_a_marks_stale_sections(tmp_path: Path):
    case = _case(tmp_path)
    r = plane_a_scan(case, persist=True)
    assert r.get("report_projection")
    assert (case / ".atlas" / "report_projection" / "manifest.json").is_file()
    add_claim(
        case,
        "Successful SMB lateral movement from host01 (T1021.002)",
        confidence="CONFIRMED",
    )
    r2 = plane_a_scan(case, persist=True)
    stale = r2.get("affected_report_sections") or []
    assert "detailed_findings" in stale
    assert "exec_summary" in stale
    assert "recommendations" in stale
    assert "key_findings" in stale


def test_bind_and_regenerate_with_fake_llm(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(
        case,
        "Interactive RDP session as Administrator from 203.0.113.71",
        confidence="CONFIRMED",
        temporal_qualifier="first interactive session",
    )
    add_claim(
        case,
        "ExampleLocker ransomware encrypted files (T1486)",
        confidence="CONFIRMED",
    )
    bind_claims_to_sections(case)
    mark_stale_sections(case, force_all=True)

    def fake_gen(ctx, sec):
        return (
            f"## {ctx['title']}\n\n"
            f"Generated from {len(ctx.get('claims') or [])} claims / "
            f"{len(ctx.get('conclusions') or [])} conclusions.\n\n"
            f"Evidence:\n- projection test\n\n"
            f"Confidence: CONFIRMED\n"
        )

    gen = regenerate_sections(case, generator=fake_gen, only_stale=True)
    assert gen["regenerated"]
    assert not gen["errors"]
    m = load_manifest(case)
    assert m["sections"]["detailed_findings"]["status"] == "current"
    assert m["sections"]["detailed_findings"]["content_sha256"]
    assert len(m["sections"]["detailed_findings"]["claim_ids"]) == 2
    tactics = m["sections"]["detailed_findings"].get("finding_tactics") or {}
    assert any("impact" in tags for tags in tactics.values())
    assert any("initial_access" in tags for tags in tactics.values())

    asm = assemble_report(case)
    assert asm["success"]
    text = Path(asm["output_path"]).read_text(encoding="utf-8")
    assert "Detailed Findings" in text or "4. Detailed" in text
    assert "Table of Contents" in text or "Inhaltsverzeichnis" in text
    assert "source of truth" in text.lower() or "quelle der wahrheit" in text.lower()


def test_cross_section_dependency_propagation(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(case, "Brute-force authentication attack T1110", confidence="CONFIRMED")
    bind_claims_to_sections(case)
    m = load_manifest(case)
    for sid, sec in m["sections"].items():
        sec["status"] = "current"
        sec["binding_fingerprint"] = "x"
    from core.report_projection import save_manifest
    save_manifest(case, m)
    m = bind_claims_to_sections(case)
    df_claims = m["sections"]["detailed_findings"]["claim_ids"]
    assert df_claims
    result = mark_stale_sections(case, dirty_node_ids=df_claims)
    stale = set(result["stale_sections"])
    assert "detailed_findings" in stale
    assert "exec_summary" in stale
    assert "timeline" in stale
    assert "key_findings" in stale


def test_section_context_from_graph_not_markdown(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    a = add_claim(case, "No successful logon", confidence="LIKELY")
    b = add_claim(case, "Successful network logon confirmed", confidence="CONFIRMED")
    add_conflict(case, "Auth disagreement", claim_ids=[a["node_id"], b["node_id"]])
    bind_claims_to_sections(case)
    ctx = section_context(case, "appendix")
    assert ctx["conflicts"]
    assert "Appendix" in ctx["title"] or "Anhang" in ctx["title"]
    # Legacy alias
    assert resolve_section_id("conflicts") == "appendix"
    assert resolve_section_id("lateral_movement") == "detailed_findings"


def test_deterministic_resilient_projection(tmp_path: Path):
    """Phase 7 reliability: project without LLM via deterministic fallback."""
    from core.investigation_state import project_report_from_state
    from core.report_projection import deterministic_section_generator

    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(
        case,
        "Successful SMB lateral movement from host01 (T1021.002)",
        confidence="CONFIRMED",
        host="host01",
    )
    r = project_report_from_state(
        case,
        regenerate_stale=True,
        generator=deterministic_section_generator,
        output_path=str(case / "reports" / "ProjTest_host01_report.md"),
    )
    assert r["success"]
    assert r["report_scope"] == "host"
    assert r["report_host"] == "host01"
    assert "Current Investigation State" in r["markdown"] or "projection" in r["markdown"].lower()
    assert "section:detailed_findings" in r["markdown"]
    assert "claims:" in r["markdown"]
    assert r["regenerate"].get("regenerated")
    assert "F-001" in r["markdown"] or "Key Findings" in r["markdown"]


def test_host_filter_excludes_other_host_claims(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(
        case,
        "Successful SMB lateral movement from host01 (T1021.002)",
        confidence="CONFIRMED",
        host="host01",
    )
    add_claim(
        case,
        "ExampleLocker ransomware encrypted files on host02 (T1486)",
        confidence="CONFIRMED",
        host="host02",
    )
    m = bind_claims_to_sections(case, host="host01", scope="host")
    assert m["sections"]["detailed_findings"]["claim_ids"]
    all_bound = []
    for sec in m["sections"].values():
        all_bound.extend(sec.get("claim_ids") or [])
    from core.claim_graph import load_graph
    g = load_graph(case)
    client_ids = [
        nid for nid, n in g["nodes"].items()
        if n.get("host") == "host02"
    ]
    assert client_ids
    assert not any(cid in all_bound for cid in client_ids)


def test_gaps_section_sees_the_whole_case_not_only_the_gaps(tmp_path: Path):
    """One UNCONFIRMED claim among many must not become "the case".

    Binding only gap-flagged claims lets the Evidence Gaps section describe
    a case of many claims as resting on a single unconfirmed source, while
    the report's other sections list confirmed findings.
    """
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(case, "Ransomware encrypted the share on WS-EXAMPLE at 12:00:00 UTC",
              confidence="CONFIRMED")
    add_claim(case, "Remote logon to WS-EXAMPLE from 203.0.113.7", confidence="LIKELY")
    add_claim(case, "The proxy log for the incident window is missing",
              confidence="UNCONFIRMED")
    bind_claims_to_sections(case)

    manifest = load_manifest(case)
    gaps = manifest["sections"]["gaps"]
    assert len(gaps["claim_ids"]) == 3, "the section must see every claim"
    assert len(gaps["priority_claim_ids"]) == 1, "only the gap-flagged one"

    ctx = section_context(case, "gaps")
    assert len(ctx["claims"]) == 3
    statements = " ".join(c.get("statement", "") for c in ctx["claims"])
    assert "Ransomware" in statements, "confirmed work must be visible here"
    assert "do NOT characterise the investigation as a whole" in ctx["style"]


def test_section_context_selects_nodes_for_the_requested_report(tmp_path: Path):
    """A host report's sections see only that host's beliefs.

    The binding in the manifest is whatever the last caller wrote (Plane A
    rebinds the whole case after every scan), so the scope a section is being
    written for has to be applied when the context is built, not trusted to
    an earlier bind.
    """
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(case, "Successful SMB lateral movement from host01 (T1021.002)",
              confidence="CONFIRMED", host="host01")
    add_claim(case, "ExampleLocker ransomware encrypted files on host02 (T1486)",
              confidence="CONFIRMED", host="host02")
    add_claim(case, "Domain-wide credential theft across host01 and host02",
              confidence="LIKELY", scope="estate")
    bind_claims_to_sections(case)

    whole = section_context(case, "detailed_findings", report_scope="case")
    assert len(whole["claims"]) == 3

    one = section_context(case, "detailed_findings",
                          report_scope="host", report_host="host01")
    assert [c["host"] for c in one["claims"]] == ["host01"]
    assert one["claim_ids"] == [c["id"] for c in one["claims"]]


class _Provider:
    name = "stub"
    model = "stub-model"
    api_key = "k"
    base_url = "http://stub.invalid/v1"

    def chat_url(self):
        return "http://stub.invalid/v1/chat/completions"

    def headers(self):
        return {}


class _HttpxReply:
    """What core.llmhub.post_chat gets back. The section generator moved onto
    the shared transport, so these tests substitute that rather than urllib."""

    def __init__(self, text: str, finish: str = "stop"):
        self._text, self._finish = text, finish
        self.status_code, self.text = 200, ""

    def raise_for_status(self):
        return None

    def json(self):
        return {"choices": [{"message": {"role": "assistant",
                                         "content": self._text},
                             "finish_reason": self._finish}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 5}}


class _Reply:
    def __init__(self, text: str):
        self._text = text

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        import json
        return json.dumps(
            {"choices": [{"message": {"content": self._text}}]}).encode()


def _section_setup(tmp_path: Path, monkeypatch):
    from core import providers
    from core.execution_log import ExecutionLog
    import core.report_projection as rp

    case = _case(tmp_path)
    (case / "analysis").mkdir()
    plane_a_scan(case, persist=True)
    add_claim(case, "Remote logon to host01 from 203.0.113.7",
              confidence="LIKELY", host="host01")
    bind_claims_to_sections(case)
    ctx = section_context(case, "exec_summary")
    sec = load_manifest(case)["sections"]["exec_summary"]
    monkeypatch.setattr(providers, "resolve", lambda name="": _Provider())
    monkeypatch.setattr(rp, "_PROVIDER_DOWN_UNTIL", [0.0])
    log = ExecutionLog()
    log.configure("ProjTest", str(case / "analysis" / "trace.json"))
    monkeypatch.setattr("core.execution_log.log", log)
    return ctx, sec, log


def test_section_call_is_bounded_and_leaves_a_trace(tmp_path: Path, monkeypatch):
    """A model call that does not answer within its budget is abandoned:
    the section falls back to deterministic prose, says so, and the trace
    shows the call starting and being given up."""
    import time

    import httpx

    from core.report_projection import resilient_section_generator

    import threading

    ctx, sec, log = _section_setup(tmp_path, monkeypatch)
    monkeypatch.setattr("core.paths.REPORT_SECTION_TIMEOUT", 1)
    release = threading.Event()

    def hang(url, json=None, headers=None, timeout=None):
        release.wait(6)
        return _HttpxReply("late")

    monkeypatch.setattr(httpx, "post", hang)
    t0 = time.monotonic()
    prose = resilient_section_generator(ctx, sec)
    assert time.monotonic() - t0 < 4
    assert prose.strip()
    assert sec["generator"] == "deterministic_fallback"
    kinds = [(e["type"], e.get("tool")) for e in log._entries]
    assert ("call_initiated", "report_section:exec_summary") in kinds
    assert ("call_abandoned", "report_section:exec_summary") in kinds
    # The abandoned call finishes here, not inside a later test, where it
    # would be recorded under that test's usage context.
    release.set()
    for worker in threading.enumerate():
        if worker.name.startswith("atlas-timeout:report_section"):
            worker.join(5)


def test_section_call_success_leaves_a_trace(tmp_path: Path, monkeypatch):
    import httpx

    from core.report_projection import resilient_section_generator

    ctx, sec, log = _section_setup(tmp_path, monkeypatch)
    monkeypatch.setattr(
        httpx, "post",
        lambda url, json=None, headers=None, timeout=None:
            _HttpxReply("The host was accessed remotely."))
    prose = resilient_section_generator(ctx, sec)
    assert prose == "The host was accessed remotely."
    assert sec["generator"] == "llm"
    kinds = [(e["type"], e.get("tool") or e.get("cmd")) for e in log._entries]
    assert ("call_initiated", "report_section:exec_summary") in kinds
    assert ("tool_call", "<py>:report_section:exec_summary") in kinds
