"""AI autofill for CASE.md's Evidence Links table and prior-knowledge section."""
from __future__ import annotations

from pathlib import Path

from core.case_autofill import (
    STANDARD_REQUEST,
    ask_llm_about_unsure,
    ask_llm_to_reformat_prior_knowledge,
    build_proposal,
    splice_case_md,
    splice_prior_knowledge,
)

TEMPLATE_MD = """# Case: Demo

**Case ID:** Demo

## Investigation Requests

<!-- Append one bullet per request, for example:
- Determine whether the workstation was compromised.
-->

## What you already know

<!-- Optional. Free text; one bullet per item works well. -->

## Evidence Links

<!-- Optional but recommended -->

| Label | Kind | Path | Notes |
|-------|------|------|-------|
| <HOST> | disk | evidence/<HOST>/<image>.vmdk | <descriptor or E01> |
| <EDR_NAME> | alias | <HOST> | EDR device name for the same host |
| <account> | principal | | compromised account |

<!--
CASE.md is the investigator work inbox.
-->
"""


def _case_with(tmp_path: Path, files: dict[str, bytes], md: str = TEMPLATE_MD) -> Path:
    case = tmp_path / "Demo"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    for rel, data in files.items():
        p = ev / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    (case / "CASE.md").write_text(md, encoding="utf-8")
    return case


class FakeClient:
    def __init__(self, content: str):
        self._content = content

    def chat(self, messages, max_tokens=2048):
        class R:
            pass
        r = R()
        r.content = self._content
        return r


def test_build_proposal_splits_confident_vs_unsure(tmp_path):
    case = _case_with(tmp_path, {
        "HOST1/HOST1.vmdk": b"fake",
        "weird.xyz": b"???",
    })
    proposal = build_proposal(case)
    assert proposal["rows"] == [{
        "path": "evidence/HOST1/HOST1.vmdk", "label": "HOST1", "kind": "disk",
        "notes": "", "class": "disk", "size": 4,
    }]
    assert len(proposal["unsure"]) == 1
    assert proposal["unsure"][0]["path"] == "evidence/weird.xyz"
    assert proposal["unsure"][0]["class"] == "file"
    # Template's placeholder bullets don't count as real requests.
    assert proposal["investigation_requests_empty"] is True


def test_build_proposal_skips_already_linked_paths(tmp_path):
    md = TEMPLATE_MD.replace(
        "| <HOST> | disk | evidence/<HOST>/<image>.vmdk | <descriptor or E01> |",
        "| HOST1 | disk | evidence/HOST1/HOST1.vmdk | already linked |",
    )
    case = _case_with(tmp_path, {"HOST1/HOST1.vmdk": b"fake"}, md=md)
    proposal = build_proposal(case)
    assert proposal["rows"] == []


def test_ask_llm_about_unsure_confident_and_question():
    unsure = [
        {"path": "evidence/a.xyz", "label": "a", "size": 1},
        {"path": "evidence/b.xyz", "label": "b", "size": 2},
    ]
    client = FakeClient(
        '[{"label": "HOST9", "kind": "pcap", "notes": "renamed capture", "question": ""},'
        ' {"label": "b", "kind": "other", "notes": "", "question": "what is this?"}]'
    )
    resolved = ask_llm_about_unsure(unsure, client)
    assert resolved[0]["kind"] == "pcap"
    assert resolved[0]["question"] == ""
    assert resolved[1]["question"] == "what is this?"


def test_ask_llm_about_unsure_empty_input_skips_call():
    assert ask_llm_about_unsure([], client=None) == []


def test_splice_case_md_drops_placeholders_and_adds_rows():
    new_md = splice_case_md(TEMPLATE_MD, [
        {"label": "HOST1", "kind": "disk", "path": "evidence/HOST1/HOST1.vmdk", "notes": ""},
    ])
    assert "<HOST>" not in new_md
    assert "<EDR_NAME>" not in new_md
    assert "| HOST1 | disk | evidence/HOST1/HOST1.vmdk |  |" in new_md


def test_splice_case_md_dedupes_existing_paths():
    md = TEMPLATE_MD.replace(
        "| <HOST> | disk | evidence/<HOST>/<image>.vmdk | <descriptor or E01> |",
        "| HOST1 | disk | evidence/HOST1/HOST1.vmdk | already here |",
    )
    new_md = splice_case_md(md, [
        {"label": "HOST1", "kind": "disk", "path": "evidence/HOST1/HOST1.vmdk", "notes": "dup"},
    ])
    assert new_md.count("evidence/HOST1/HOST1.vmdk") == 1
    assert "already here" in new_md


def test_splice_case_md_adds_standard_request_when_asked():
    new_md = splice_case_md(TEMPLATE_MD, [], add_standard_request=True)
    assert f"- {STANDARD_REQUEST}" in new_md


def test_splice_case_md_raises_without_evidence_links_table():
    stripped = "# Case: Demo\n\n## Investigation Requests\n\n- do it\n"
    try:
        splice_case_md(stripped, [{"label": "x", "kind": "other", "path": "", "notes": ""}])
        assert False, "expected ValueError"
    except ValueError:
        pass


# ── What you already know ─────────────────────────────────────────────────

INTAKE = ("Note from the requester: the account jane.doe@example.test is "
          "believed compromised, and its Windows logon jdoe may have been used "
          "to attach a removable drive to the host. Find out which removable "
          "drives were attached.")

REWRITE = (
    '{"knowledge": ['
    '"- Compromised account: jane.doe@example.test. Windows user name: jdoe '
    '(Windows account, domain not given).", '
    '"Working theory: a removable drive was attached to the host with the '
    'Windows logon jdoe."], '
    '"requests": ["Find out which removable drives were attached to the host."]}'
)


def _md_with_intake(intake: str) -> str:
    return TEMPLATE_MD.replace(
        "<!-- Optional. Free text; one bullet per item works well. -->\n",
        "<!-- Optional. Free text; one bullet per item works well. -->\n\n" + intake + "\n")


def test_build_proposal_reports_prior_knowledge_without_comments(tmp_path):
    case = _case_with(tmp_path, {}, md=_md_with_intake(INTAKE))
    assert build_proposal(case)["prior_knowledge"] == INTAKE
    case2 = _case_with(tmp_path / "other", {})
    assert build_proposal(case2)["prior_knowledge"] == ""


def test_reformat_prior_knowledge_splits_facts_from_requests():
    out = ask_llm_to_reformat_prior_knowledge(INTAKE, FakeClient(REWRITE))
    assert out["knowledge"][0].startswith("Compromised account: jane.doe@example.test")
    assert out["knowledge"][0] == out["knowledge"][0].lstrip("- ")
    assert out["requests"] == ["Find out which removable drives were attached to the host."]
    assert out["dropped"] == []


def test_reformat_prior_knowledge_names_indicators_the_rewrite_lost():
    out = ask_llm_to_reformat_prior_knowledge(
        INTAKE, FakeClient('{"knowledge": ["a removable drive was used"], "requests": []}'))
    assert out["dropped"] == ["email:jane.doe@example.test"]


def test_a_fenced_block_reaches_the_rewrite_and_its_loss_is_named(tmp_path):
    sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    fenced = f"- We suspect data theft from CORP-WS01.\n\n```\nsha256 {sha}\n```"
    case = _case_with(tmp_path, {}, md=_md_with_intake(fenced))
    prior = build_proposal(case)["prior_knowledge"]
    assert sha in prior
    out = ask_llm_to_reformat_prior_knowledge(
        prior, FakeClient('{"knowledge": ["We suspect data theft from CORP-WS01."], "requests": []}'))
    assert out["dropped"] == [f"sha256:{sha}"]


def test_reformat_prior_knowledge_unusable_reply_is_none():
    assert ask_llm_to_reformat_prior_knowledge(INTAKE, FakeClient("no json here")) is None
    assert ask_llm_to_reformat_prior_knowledge(INTAKE, FakeClient('{"knowledge": []}')) is None
    assert ask_llm_to_reformat_prior_knowledge("", client=None) is None


def test_splice_prior_knowledge_keeps_comments_and_the_rest_of_the_file():
    from core.case_knowledge import section_text
    from core.investigation_tasks import parse_case_requests
    md = _md_with_intake(INTAKE)
    new_md = splice_prior_knowledge(
        md, ["Compromised account: jane.doe@example.test.", "- Windows user: EX\\jdoe"],
        requests=["Find out which removable drives were attached to the host."])
    assert "<!-- Optional. Free text; one bullet per item works well. -->" in new_md
    assert INTAKE not in new_md
    assert section_text(new_md) == (
        "- Compromised account: jane.doe@example.test.\n- Windows user: EX\\jdoe")
    assert parse_case_requests(new_md) == [
        "Find out which removable drives were attached to the host."]
    # Everything outside the two sections is byte-identical.
    tail = new_md[new_md.index("## Evidence Links"):]
    assert tail == md[md.index("## Evidence Links"):]
    assert new_md.startswith(md[:md.index("## Investigation Requests")])


def test_splice_prior_knowledge_does_not_repeat_a_request_already_there():
    md = _md_with_intake(INTAKE).replace(
        "## Investigation Requests\n", "## Investigation Requests\n\n- Find the USB devices.\n")
    new_md = splice_prior_knowledge(md, ["fact"], requests=["find the usb devices.", "Another one."])
    assert new_md.count("USB devices.") + new_md.count("usb devices.") == 1
    assert "- Another one." in new_md


def test_splice_prior_knowledge_raises_without_the_section():
    try:
        splice_prior_knowledge("# Case: Demo\n\n## Evidence Links\n", ["x"])
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_append_requests_creates_the_section_when_missing():
    from core.case_autofill import append_requests
    md = "# Case: Demo\n\n## What you already know\n\n- a fact\n"
    out = append_requests(md, ["Was data taken?"])
    assert out.endswith("## Investigation Requests\n\n- Was data taken?\n")
    assert "- a fact" in out
    assert append_requests(out, ["- was DATA taken?"]) == out


def test_hidden_requests_are_not_an_empty_section(tmp_path):
    """Requests an unclosed block hides are still the analyst's: autofill
    reports the block and adds no standard question on top of them."""
    from core.case_autofill import build_proposal
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "CASE.md").write_text(
        "# Case CASE-A\n\n## What you already know\n\n```\npasted line\n\n"
        "## Investigation Requests\n\n- Which account logged on to CORP-DC01?\n",
        encoding="utf-8")
    proposal = build_proposal(case)
    assert proposal["unclosed_fence"]["line"] == 5
    assert proposal["investigation_requests_empty"] is False
