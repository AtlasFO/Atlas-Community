"""SECOND BRAIN CONTEXT injection into the analyst system prompt."""

import json
from pathlib import Path

import pytest

from agent.prompts import build_system_prompt, _MEMORY_BYTES_CAP, _NOTES_BYTES_CAP

NOTE = """---
title: "{title}"
type: "{type}"
created: "2026-07-01"
updated: "2026-07-01"
status: "active"
source_classification: "{classification}"
confidence: "high"
tags: [{tags}]
related: []
source: {{type: "manual", url: "", description: ""}}
entities: {{cases: [], tools: [], techniques: [], actors: [], cves: []}}
---

# {title}

{body}
"""


@pytest.fixture
def brain(tmp_path, monkeypatch):
    root = tmp_path / "brain"
    (root / "memory").mkdir(parents=True)
    (root / "wiki/tools").mkdir(parents=True)
    (root / "AGENTS.md").write_text("# router")
    (root / "memory/MEMORY.md").write_text(
        "# Atlas Durable Memory\n\n- coverage_report must run every case\n")
    (root / "memory/preferences.md").write_text("- UTC timestamps\n")
    (root / "wiki/tools/volatility.md").write_text(NOTE.format(
        title="Volatility symbol gotcha", type="tool",
        classification="internal", tags="volatility, memory-forensics",
        body="Win11 24H2 images need the extra symbol pack."))
    (root / "wiki/tools/secret.md").write_text(NOTE.format(
        title="Confidential trick", type="tool",
        classification="confidential", tags="volatility",
        body="do not leak CONFIDENTIALMARKER"))
    monkeypatch.setenv("ATLAS_BRAIN_ROOT", str(root))
    monkeypatch.delenv("ATLAS_NO_BRAIN", raising=False)
    return root


@pytest.fixture
def case(tmp_path):
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "evidence" / "memdump.vmem").write_bytes(b"\x00")
    return case


def test_injection_with_memory_and_matched_notes(brain, case):
    prompt = build_system_prompt(case)
    assert "# SECOND BRAIN CONTEXT" in prompt
    assert "coverage_report must run every case" in prompt
    assert "Volatility symbol gotcha" in prompt          # matched via .vmem tags
    assert "never write brain/memory" in prompt.lower()


def test_raw_evidence_retrieves_memory_forensics_note(brain, tmp_path):
    """.raw is ambiguous (disk OR RAM). It must retrieve memory-forensics notes,
    not just disk-image ones — with .raw mapped disk-only, a RAM dump named
    .raw misses every memory note."""
    case = tmp_path / "rawcase"
    (case / "evidence").mkdir(parents=True)
    (case / "evidence" / "MemoryDump_Lab.raw").write_bytes(b"\x00")
    prompt = build_system_prompt(case)
    assert "Volatility symbol gotcha" in prompt  # tagged volatility/memory-forensics


def test_bin_evidence_maps_to_ics_tags(brain, tmp_path):
    """.bin (PLC/embedded dumps) was unmapped, so ICS notes could never be
    retrieved. It must now resolve to ics/embedded tags."""
    from agent.prompts import _EVIDENCE_TAGS
    assert "ics" in _EVIDENCE_TAGS.get(".bin", [])
    (brain / "wiki/tools/plc.md").write_text(NOTE.format(
        title="Schneider M221 UMAS note", type="technique",
        classification="internal", tags="ics, modbus, plc",
        body="Modbus FC 0x5A carries UMAS engineering traffic."))
    case = tmp_path / "bincase"
    (case / "evidence").mkdir(parents=True)
    (case / "evidence" / "ExtRAM_dump.bin").write_bytes(b"\x00")
    prompt = build_system_prompt(case)
    assert "Schneider M221 UMAS note" in prompt


def test_confidential_never_injected(brain, case):
    prompt = build_system_prompt(case)
    assert "CONFIDENTIALMARKER" not in prompt
    assert "Confidential trick" not in prompt


def test_disabled_by_env(brain, case, monkeypatch):
    monkeypatch.setenv("ATLAS_NO_BRAIN", "1")
    assert "# SECOND BRAIN CONTEXT" not in build_system_prompt(case)


def test_absent_brain_dir_yields_no_section(tmp_path, case, monkeypatch):
    monkeypatch.setenv("ATLAS_BRAIN_ROOT", str(tmp_path / "nope"))
    assert "# SECOND BRAIN CONTEXT" not in build_system_prompt(case)


def test_byte_caps_respected(brain, case):
    (brain / "memory/MEMORY.md").write_text("X" * 50_000)
    (brain / "wiki/tools/volatility.md").write_text(NOTE.format(
        title="Volatility symbol gotcha", type="tool",
        classification="internal", tags="volatility, memory-forensics",
        body="Y" * 50_000))
    prompt = build_system_prompt(case)
    start = prompt.index("# SECOND BRAIN CONTEXT")
    section = prompt[start:]
    assert len(section) < _MEMORY_BYTES_CAP + _NOTES_BYTES_CAP + 2000


def test_no_case_dir_still_injects_memory(brain):
    prompt = build_system_prompt(None)
    assert "coverage_report must run every case" in prompt


def test_live_wiki_concepts_listed_in_catalogue(brain, case):
    """Concepts appear as a title catalogue; full text comes from brain.consult."""
    (brain / "wiki/concepts").mkdir(parents=True)
    (brain / "wiki/concepts/carry-leads.md").write_text(NOTE.format(
        title="Carry leads to completion", type="concept",
        classification="internal", tags="workflow",
        body="Attempt the decryption before wrapping up."))
    prompt = build_system_prompt(case)
    assert "Lessons catalogue" in prompt
    assert "brain.consult" in prompt
    assert "Carry leads to completion" in prompt
    # Full body is no longer dumped into the system prompt.
    assert "Attempt the decryption before wrapping up." not in prompt


def test_pinned_concept_survives_count_cap_over_newer_ones(brain, case):
    """A `pin: true` concept sorts ahead of newer concepts in the catalogue."""
    from agent.prompts import _CONCEPTS_MAX
    concepts = brain / "wiki/concepts"
    concepts.mkdir(parents=True)
    pinned = NOTE.format(
        title="Pinned safety guard PINNEDGUARDMARKER", type="concept",
        classification="internal", tags="workflow",
        body="body not injected").replace(
        'updated: "2026-07-01"', 'updated: "2026-01-01"\npin: true')
    (concepts / "pinned.md").write_text(pinned)
    for i in range(_CONCEPTS_MAX + 3):
        (concepts / f"newer{i:02d}.md").write_text(NOTE.format(
            title=f"Newer concept {i:02d}", type="concept",
            classification="internal", tags="workflow",
            body=f"body {i}").replace(
            'updated: "2026-07-01"', f'updated: "2026-08-{(i % 28) + 1:02d}"'))
    prompt = build_system_prompt(case)
    assert "PINNEDGUARDMARKER" in prompt
    assert "Newer concept 00" in prompt or "Newer concept" in prompt


def _manifest(case):
    return json.loads(
        (case / "analysis" / "brain_injection.json").read_text())


def test_injection_manifest_written(brain, case):
    """Prompt build persists what was injected per tier, so capture_run can
    log it into the run summary (effectiveness measurement, not inference)."""
    build_system_prompt(case)
    m = _manifest(case)
    assert m["memory"]["files"] == ["MEMORY.md", "preferences.md"]
    assert m["memory"]["truncated"] is False
    titles = [n["title"] for n in m["retrieval"]["notes"]]
    assert "Volatility symbol gotcha" in titles
    assert all(n["status"] == "catalogue" for n in m["retrieval"]["notes"])
    assert "Confidential trick" not in titles
    assert "memory-forensics" in m["retrieval"]["tags"]
    assert m["generated_at"]


def test_manifest_records_cap_drops(brain, case, monkeypatch):
    """Titles beyond _CONCEPTS_MAX are recorded as dropped:count-cap."""
    import agent.prompts as prompts
    from agent.prompts import _CONCEPTS_MAX
    monkeypatch.setattr(prompts, "_CONCEPTS_MAX", 4)
    concepts = brain / "wiki/concepts"
    concepts.mkdir(parents=True)
    for i in range(6):
        (concepts / f"c{i:02d}.md").write_text(NOTE.format(
            title=f"Concept {i:02d}", type="concept",
            classification="internal", tags="workflow",
            body=f"body {i}").replace(
            'updated: "2026-07-01"', f'updated: "2026-08-{i+1:02d}"'))
    build_system_prompt(case)
    statuses = {c["title"]: c["status"] for c in _manifest(case)["concepts"]}
    assert len(statuses) == 6
    assert sum(1 for s in statuses.values() if s == "catalogue") == 4
    assert sum(1 for s in statuses.values()
               if s == "dropped:count-cap") == 2
    newest = "Concept 05"
    assert statuses[newest] == "catalogue"


def test_no_manifest_when_brain_disabled(brain, case, monkeypatch):
    monkeypatch.setenv("ATLAS_NO_BRAIN", "1")
    build_system_prompt(case)
    assert not (case / "analysis" / "brain_injection.json").exists()


def test_retired_concepts_never_injected(brain, case):
    """A concept retired to inbox/processed/ (or marked archived) must not
    inject — otherwise a retired note keeps re-leaking a case answer key."""
    (brain / "inbox/processed").mkdir(parents=True)
    (brain / "inbox/processed/leaky.md").write_text(NOTE.format(
        title="Leaky retired concept", type="concept",
        classification="internal", tags="workflow",
        body="the key is RETIREDANSWERKEY"))
    (brain / "wiki/concepts").mkdir(parents=True)
    archived = NOTE.format(
        title="Archived in place", type="concept",
        classification="internal", tags="workflow",
        body="ARCHIVEDMARKER should not inject").replace(
        'status: "active"', 'status: "archived"')
    (brain / "wiki/concepts/archived.md").write_text(archived)
    prompt = build_system_prompt(case)
    assert "RETIREDANSWERKEY" not in prompt
    assert "ARCHIVEDMARKER" not in prompt


# ---- Tier D: client environment baselines ---------------------------------

ENV_NOTE = """---
title: "{title}"
type: "environment"
client: "{client}"
created: "2026-07-01"
updated: "2026-07-01"
last_verified: "2026-07-01"
status: "{status}"
source_classification: "{classification}"
confidence: "high"
tags: [{tags}]
related: []
source: {{type: "{source_type}", url: "", description: ""}}
entities: {{cases: [], tools: [], techniques: [], actors: [], cves: []}}
---

# {title}

{body}
"""


def _env_note(brain, name="ad.md", title="ACME AD baseline",
              client="acme-corp", body="ACMEBASELINE: DC01/DC02, JUMP01.",
              source_type="client_provided", status="active",
              classification="internal", tags="acme-corp"):
    d = brain / "wiki/environments" / client
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(ENV_NOTE.format(
        title=title, client=client, body=body, source_type=source_type,
        status=status, classification=classification, tags=tags))


def _declare_engagement(case, client="acme-corp"):
    (case / "engagement.yaml").write_text(f"client: {client}\n")


def test_env_injected_for_matching_client_ungraded_case(brain, case):
    _env_note(brain)
    _declare_engagement(case)
    prompt = build_system_prompt(case)
    assert "## Client environment baseline — acme-corp" in prompt
    assert "ACMEBASELINE" in prompt
    assert "NOT findings and NOT indicators" in prompt
    assert "last verified 2026-07-01" in prompt


def test_env_hard_off_when_ground_truth_present(brain, case):
    """A graded case must never see client-scoped knowledge, wherever the
    grading key lives."""
    _env_note(brain)
    _declare_engagement(case)
    (case / "ground_truth.json").write_text("{}")
    assert "ACMEBASELINE" not in build_system_prompt(case)
    (case / "ground_truth.json").unlink()
    (case / "evidence" / "ground_truth.json").write_text("{}")
    assert "ACMEBASELINE" not in build_system_prompt(case)


def test_env_inert_without_engagement_declaration(brain, case):
    """Byte-identical prompts with and without environment notes in the brain
    when the case declares no client — proves training runs are untouched."""
    baseline = build_system_prompt(case)
    _env_note(brain)
    assert build_system_prompt(case) == baseline


def test_env_not_injected_on_client_mismatch(brain, case):
    _env_note(brain)
    _declare_engagement(case, client="other-corp")
    prompt = build_system_prompt(case)
    assert "ACMEBASELINE" not in prompt
    assert "Client environment baseline" not in prompt


def test_env_agent_run_source_never_injected(brain, case):
    """Injection-side layer of the no-run-provenance rule (approve is the
    other): a baseline derived from a run is a prior solve in disguise."""
    _env_note(brain, source_type="agent_run", body="RUNSOURCEDMARKER")
    _declare_engagement(case)
    assert "RUNSOURCEDMARKER" not in build_system_prompt(case)


def test_env_archived_and_confidential_not_injected(brain, case):
    _env_note(brain, name="old.md", title="Old", status="archived",
              body="ARCHIVEDENVMARKER")
    _env_note(brain, name="conf.md", title="Conf",
              classification="confidential", body="CONFENVMARKER")
    _declare_engagement(case)
    prompt = build_system_prompt(case)
    assert "ARCHIVEDENVMARKER" not in prompt
    assert "CONFENVMARKER" not in prompt


def test_env_isolated_from_other_tiers(brain, case):
    """An environment note never leaks through Tier B (concepts) or Tier C
    (evidence-tag retrieval), even when its tags match the case evidence."""
    _env_note(brain, tags="volatility, memory-forensics",
              body="ENVISOLATIONMARKER")
    # no engagement.yaml: Tier D off, so any appearance is a leak
    assert "ENVISOLATIONMARKER" not in build_system_prompt(case)


def test_env_byte_cap_respected(brain, case):
    from agent.prompts import _ENV_BYTES_CAP
    for i in range(12):
        _env_note(brain, name=f"big{i:02d}.md", title=f"Big {i:02d}",
                  body="Z" * 5000)
    _declare_engagement(case)
    prompt = build_system_prompt(case)
    start = prompt.index("## Client environment baseline")
    end = prompt.find("## Lessons catalogue")
    section = prompt[start:end if end != -1 else None]
    assert len(section) < _ENV_BYTES_CAP + 800


def test_env_manifest_records_injection(brain, case):
    _env_note(brain)
    _declare_engagement(case)
    build_system_prompt(case)
    m = _manifest(case)
    assert m["environment"]["client"] == "acme-corp"
    titles = [n["title"] for n in m["environment"]["notes"]]
    assert "ACME AD baseline" in titles


# ── Same-case exclusion (anti-memorization guard) ────────────────────────────
# An entry whose origin.case_id names the active case is that case's own
# prior-run learning: injecting it back is memorization and silently inflates
# every repeat-training score.

def _origin_note(brain, rel, title, type_, tags, body, origin_case_id=None,
                 extra=""):
    text = NOTE.format(title=title, type=type_, classification="internal",
                       tags=tags, body=body)
    if origin_case_id is not None:
        text = text.replace(
            "related: []",
            f"related: []\norigin: {{case_id: \"{origin_case_id}\"}}")
    if extra:
        text = text.replace("related: []", f"related: []\n{extra}")
    path = brain / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _active_case(tmp_path):
    case = tmp_path / "somedir"
    (case / "evidence").mkdir(parents=True)
    (case / "evidence" / "memdump.vmem").write_bytes(b"\x00")
    (case / "CASE.md").write_text("| **Case ID** | CASE-C-1 |\n")
    return case


def test_same_case_concept_excluded(brain, tmp_path):
    case = _active_case(tmp_path)
    (brain / "wiki/concepts").mkdir(parents=True, exist_ok=True)
    _origin_note(brain, "wiki/concepts/own.md", "Own lesson SAMECASEMARKER",
                 "concept", "tiering", "lesson from this very case",
                 origin_case_id="CASE-C-1")
    _origin_note(brain, "wiki/concepts/other.md",
                 "Other lesson CROSSCASEMARKER", "concept",
                 "tiering", "lesson from another case",
                 origin_case_id="CFREDS-LEAK")
    prompt = build_system_prompt(case)
    assert "SAMECASEMARKER" not in prompt
    assert "CROSSCASEMARKER" in prompt
    m = _manifest(case)
    excluded = {e["title"]: e for e in m["excluded_same_case"]}
    assert "Own lesson SAMECASEMARKER" in excluded
    assert excluded["Own lesson SAMECASEMARKER"]["tier"] == "concepts"
    assert excluded["Own lesson SAMECASEMARKER"]["origin_case_id"] == "CASE-C-1"
    assert "case-c-1" in m["active_case_ids"]


def test_same_case_retrieval_note_excluded(brain, tmp_path):
    case = _active_case(tmp_path)
    _origin_note(brain, "wiki/tools/own-gotcha.md", "Own gotcha OWNGOTCHAMARKER",
                 "tool", "volatility, memory-forensics", "body",
                 origin_case_id="case-c")
    prompt = build_system_prompt(case)
    assert "OWNGOTCHAMARKER" not in prompt
    # the cross-case volatility note from the fixture still injects
    assert "Volatility symbol gotcha" in prompt
    m = _manifest(case)
    assert any(e["tier"] == "retrieval" and "Own gotcha" in e["title"]
               for e in m["excluded_same_case"])


def test_slug_variant_matches_dir_name(brain, tmp_path):
    """origin CASE-C-1 must match a case dir named `case-c` even without a
    CASE.md (prefix rule, shorter side >= 4 chars)."""
    case = tmp_path / "case-c"
    (case / "evidence").mkdir(parents=True)
    (case / "evidence" / "memdump.vmem").write_bytes(b"\x00")
    (brain / "wiki/concepts").mkdir(parents=True, exist_ok=True)
    _origin_note(brain, "wiki/concepts/own.md", "Own lesson SAMECASEMARKER",
                 "concept", "tiering", "body", origin_case_id="CASE-C-1")
    assert "SAMECASEMARKER" not in build_system_prompt(case)


def test_prefix_guard_rejects_sibling_cases(brain, tmp_path):
    """EXAMPLE-LAB2 is NOT the same case as example-lab5 — hyphen-boundary
    prefix only fires when one id extends the other."""
    case = tmp_path / "example-lab5"
    (case / "evidence").mkdir(parents=True)
    (case / "evidence" / "memdump.vmem").write_bytes(b"\x00")
    (brain / "wiki/concepts").mkdir(parents=True, exist_ok=True)
    _origin_note(brain, "wiki/concepts/lab2.md", "Lab2 lesson SIBLINGMARKER",
                 "concept", "tiering", "body", origin_case_id="EXAMPLE-LAB2")
    assert "SIBLINGMARKER" in build_system_prompt(case)


def test_empty_origin_injected(brain, tmp_path):
    """Hand-authored entries without origin fail open — exclusion is a
    contamination heuristic, not a hard guard."""
    case = _active_case(tmp_path)
    (brain / "wiki/concepts").mkdir(parents=True, exist_ok=True)
    _origin_note(brain, "wiki/concepts/hand.md", "Hand lesson HANDMARKER",
                 "concept", "tiering", "body not in catalogue")
    assert "HANDMARKER" in build_system_prompt(case)


def test_excluded_concepts_free_up_count_cap(brain, tmp_path):
    """Excluded same-case concepts must not consume _CONCEPTS_MAX slots."""
    from agent.prompts import _CONCEPTS_MAX
    case = _active_case(tmp_path)
    (brain / "wiki/concepts").mkdir(parents=True, exist_ok=True)
    # newest-first order: same-case notes sort first but get excluded
    for i in range(_CONCEPTS_MAX):
        _origin_note(brain, f"wiki/concepts/own{i}.md", f"Own {i}",
                     "concept", "tiering", f"OWNMARKER{i}",
                     origin_case_id="CASE-C-1",
                     extra='updated: "2026-07-10"')
    _origin_note(brain, "wiki/concepts/keep.md", "Keeper KEEPERMARKER",
                 "concept", "tiering", "body", origin_case_id="CFREDS-LEAK",
                 extra='updated: "2026-07-01"')
    prompt = build_system_prompt(case)
    assert "KEEPERMARKER" in prompt
    assert "Own 0" not in prompt


def test_same_case_exclusion_wins_over_pin(brain, tmp_path):
    case = _active_case(tmp_path)
    (brain / "wiki/concepts").mkdir(parents=True, exist_ok=True)
    _origin_note(brain, "wiki/concepts/pinned.md",
                 "Pinned own PINNEDOWNMARKER", "concept",
                 "tiering", "body", origin_case_id="CASE-C-1",
                 extra="pin: true")
    assert "PINNEDOWNMARKER" not in build_system_prompt(case)


def test_memory_same_case_line_dropped_others_survive(brain, tmp_path):
    """Tier A same-case guard is line-level: a line naming the active case is
    dropped, but surrounding curated guidance survives."""
    case = _active_case(tmp_path)
    (brain / "memory/MEMORY.md").write_text(
        "# Memory\n\n"
        "- CASE-C-1 taught us the answer key is examplesecret31\n"
        "- Always run coverage_report before the report phase\n")
    prompt = build_system_prompt(case)
    assert "examplesecret31" not in prompt          # same-case line dropped
    assert "Always run coverage_report" in prompt    # cross-case line kept
    m = _manifest(case)
    assert m["memory"]["same_case_mentions"] is True


def test_origin_less_concept_caught_by_entities_cases(brain, tmp_path):
    """A promoted concept with no origin block but entities.cases naming the
    active case must still be excluded (fail-closed on provenance)."""
    case = _active_case(tmp_path)
    (brain / "wiki/concepts").mkdir(parents=True, exist_ok=True)
    text = NOTE.format(title="Entities-only own lesson ENTITIESMARKER",
                       type="concept",
                       classification="internal", tags="tiering",
                       body="body")
    text = text.replace(
        "entities: {cases: [], tools: [], techniques: [], actors: [], "
        "cves: []}",
        "entities: {cases: [CASE-C-1], tools: [], techniques: [], "
        "actors: [], cves: []}")
    (brain / "wiki/concepts/entities-own.md").write_text(text)
    assert "ENTITIESMARKER" not in build_system_prompt(case)
