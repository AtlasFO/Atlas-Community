"""Investigation tasks — CASE.md reconcile (deterministic)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.core.test_contents_index import case  # noqa: F401

from core.investigation_tasks import (
    parse_case_request_items,
    DERIVED_PREFIX,
    fingerprint_text,
    normalize_request_text,
    parse_case_requests,
    reconcile_case_md,
    reopen_tasks_for_claims,
    update_task,
    add_derived_task,
    load_tasks,
    supersede_task,
)
from core.incremental import plane_a_scan, ensure_atlas_scaffold
from tests._edition import DEVTOOLS_SHIPPED, NO_DEV_DATA


def test_normalize_and_fingerprint():
    assert normalize_request_text("  Investigate   Host A ") == "investigate host a"
    assert fingerprint_text("Investigate Host A") == fingerprint_text(
        "  investigate   host a  "
    )
    assert fingerprint_text("Investigate Host A") != fingerprint_text(
        "Investigate Host A for persistence"
    )


def test_parse_investigation_requests_section():
    md = """# Case: X

**Case ID:** X

## Investigation Requests

- Determine whether the workstation was compromised.
- Investigate Host B.

## Evidence Files

- `evidence/foo.E01` | host | disk
"""
    reqs = parse_case_requests(md)
    assert reqs == [
        "Determine whether the workstation was compromised.",
        "Investigate Host B.",
    ]


def test_parse_scope_alias_and_compat_bullets():
    md = """# Case

## Scope

1. Find initial access.
2. Check persistence.
"""
    assert parse_case_requests(md) == [
        "Find initial access.",
        "Check persistence.",
    ]


def test_html_comments_never_become_tasks():
    """A CASE.md template may document Atlas internals inside an HTML
    comment; the bullets in that comment must not become tasks."""
    md = """# Case: X

## Investigation Requests

- Real question one?
- Real question two?

<!--
CASE.md is the investigator work inbox — not findings, not memory.

Atlas owns investigation state under .atlas/:
  - investigation_tasks.json  (task lifecycle)
  - investigation_plan.json   (pre-execution checklist)
  - claim_graph.json          (beliefs)
  - evidence_catalog.json     (evidence fingerprints)
-->
"""
    assert parse_case_requests(md) == [
        "Real question one?",
        "Real question two?",
    ]


def test_unterminated_html_comment_strips_to_eof():
    md = """## Investigation Requests

- The only real request.

<!-- documentation the template author forgot to close
- not a request
- also not a request
"""
    assert parse_case_requests(md) == ["The only real request."]


def test_fenced_code_blocks_never_become_tasks():
    md = """## Investigation Requests

- Determine initial access.

Example of how Atlas tracks state:

```
- investigation_tasks.json
- claim_graph.json
```

~~~markdown
- example bullet inside a tilde fence
~~~

- Verify lateral movement.
"""
    assert parse_case_requests(md) == [
        "Determine initial access.",
        "Verify lateral movement.",
    ]


def test_nested_bullets_are_substructure_not_requests():
    md = """## Investigation Requests

- Investigate Host B for the following:
  - persistence mechanisms
  - lateral movement traces
- Did data exfiltration occur?
"""
    assert parse_case_requests(md) == [
        "Investigate Host B for the following:",
        "Did data exfiltration occur?",
    ]


def test_comment_stripping_applies_in_compat_mode():
    """No Investigation Requests section → compat bullet collection must
    still never pick up commented/fenced content."""
    md = """# Case

Some prose.

- A body bullet request.

<!-- - commented bullet -->

```
- fenced bullet
```
"""
    assert parse_case_requests(md) == ["A body bullet request."]


def test_reconcile_withdraws_previously_ingested_doc_tasks(tmp_path: Path):
    """A store polluted by the old parser self-heals on the next reconcile:
    doc bullets no longer parse as requests, so those open tasks withdraw."""
    case = tmp_path / "case"
    case.mkdir()
    polluted = (
        "## Investigation Requests\n\n- Real question?\n\n"
        "<!--\n  - investigation_tasks.json  (task lifecycle)\n-->\n"
    )
    case_md = case / "CASE.md"
    case_md.write_text(polluted, encoding="utf-8")
    reconcile_case_md(case, persist=True)
    # Simulate the old-parser pollution directly in the store.
    store = load_tasks(case)
    from core.investigation_tasks import _make_task, save_tasks
    junk = _make_task(store, "investigation_tasks.json  (task lifecycle)")
    store["tasks"].append(junk)
    save_tasks(case, store)

    r = reconcile_case_md(case, persist=True)
    by_id = {t["id"]: t for t in load_tasks(case)["tasks"]}
    assert junk["id"] in r["dropped"]
    assert by_id[junk["id"]]["status"] == "dropped"
    real = [t for t in by_id.values() if t["text"] == "Real question?"]
    assert real and real[0]["status"] == "open"


def test_reconcile_exact_match_new_and_extended_text(tmp_path: Path):
    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text(
        "# Case\n\n## Investigation Requests\n\n"
        "- Investigate Host A\n",
        encoding="utf-8",
    )
    r1 = reconcile_case_md(case, persist=True, case_id="T")
    assert r1["counts"]["added"] == 1
    assert len(r1["added"]) == 1
    tid = r1["added"][0]

    # Same text → match, no new task
    r2 = reconcile_case_md(case, persist=True)
    assert r2["counts"]["added"] == 0
    assert tid in r2["matched"]

    # Extended wording → new task (no fuzzy merge)
    (case / "CASE.md").write_text(
        "# Case\n\n## Investigation Requests\n\n"
        "- Investigate Host A\n"
        "- Investigate Host A for persistence\n",
        encoding="utf-8",
    )
    r3 = reconcile_case_md(case, persist=True)
    assert r3["counts"]["added"] == 1
    assert len(load_tasks(case)["tasks"]) == 2


def test_withdraw_removed_open_keep_answered(tmp_path: Path):
    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Task one\n- Task two\n",
        encoding="utf-8",
    )
    r1 = reconcile_case_md(case, persist=True)
    ids = r1["added"]
    assert len(ids) == 2
    from core.claim_graph import add_claim
    cid = add_claim(case, "Task one was established by evidence.",
                    confidence="LIKELY", enforce_validation=False)["node_id"]
    assert update_task(case, ids[0], status="answered",
                       related_claim_ids=[cid])["success"]

    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Task two\n",
        encoding="utf-8",
    )
    r2 = reconcile_case_md(case, persist=True)
    store = load_tasks(case)
    by_id = {t["id"]: t for t in store["tasks"]}
    assert by_id[ids[0]]["status"] == "answered"  # history preserved
    assert by_id[ids[1]]["status"] != "dropped"  # still in CASE.md
    # Task one removed while answered → stays answered; if it were open it'd drop
    # Add a third open then remove it
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Task two\n- Task three\n",
        encoding="utf-8",
    )
    r3 = reconcile_case_md(case, persist=True)
    tid3 = r3["added"][0]
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Task two\n",
        encoding="utf-8",
    )
    r4 = reconcile_case_md(case, persist=True)
    assert tid3 in r4["dropped"]
    assert load_tasks(case)["tasks"]
    by_id = {t["id"]: t for t in load_tasks(case)["tasks"]}
    assert by_id[tid3]["status"] == "dropped"


def test_edit_wording_creates_new_task_drops_old_no_fuzzy_merge(tmp_path: Path):
    """Reword → new task + old dropped; never silent merge."""
    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Investigate Host A\n",
        encoding="utf-8",
    )
    r1 = reconcile_case_md(case, persist=True)
    old_id = r1["added"][0]
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n"
        "- Investigate Host A for persistence\n",
        encoding="utf-8",
    )
    r2 = reconcile_case_md(case, persist=True)
    assert len(r2["added"]) == 1
    new_id = r2["added"][0]
    assert new_id != old_id
    assert old_id in r2["dropped"]
    by_id = {t["id"]: t for t in load_tasks(case)["tasks"]}
    assert by_id[old_id]["status"] == "dropped"
    assert by_id[old_id].get("superseded_by") in ("", None)
    assert by_id[new_id]["status"] == "open"
    assert "persistence" in by_id[new_id]["text"]


def test_supersede_task_explicit_link(tmp_path: Path):
    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Investigate Host A\n",
        encoding="utf-8",
    )
    r1 = reconcile_case_md(case, persist=True)
    old_id = r1["added"][0]
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n"
        "- Investigate Host A for persistence\n",
        encoding="utf-8",
    )
    r2 = reconcile_case_md(case, persist=True)
    new_id = r2["added"][0]
    out = supersede_task(case, old_id, new_id)
    assert out["success"] is True
    by_id = {t["id"]: t for t in load_tasks(case)["tasks"]}
    assert by_id[old_id]["status"] == "dropped"
    assert by_id[old_id]["superseded_by"] == new_id


def test_load_migrates_withdrawn_to_dropped(tmp_path: Path):
    case = tmp_path / "case"
    case.mkdir()
    atlas = case / ".atlas"
    atlas.mkdir()
    (atlas / "investigation_tasks.json").write_text(
        '{"schema_version":"1.0","case_id":"T","next_id":2,"tasks":['
        '{"id":"task-0001","text":"Old","status":"withdrawn",'
        '"related_claim_ids":[],"created_at":"t","updated_at":"t"}]}',
        encoding="utf-8",
    )
    store = load_tasks(case)
    assert store["tasks"][0]["status"] == "dropped"
    # Persist rewrite so on-disk no longer carries the legacy enum.
    on_disk = (atlas / "investigation_tasks.json").read_text(encoding="utf-8")
    assert '"dropped"' in on_disk
    assert '"withdrawn"' not in on_disk


def test_derived_not_withdrawn(tmp_path: Path):
    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Investigate Host B\n",
        encoding="utf-8",
    )
    reconcile_case_md(case, persist=True)
    d = add_derived_task(
        case,
        "[derived] Re-check Host A for staging indicators",
    )
    assert d["created"] is True
    reconcile_case_md(case, persist=True)
    store = load_tasks(case)
    derived = [t for t in store["tasks"] if t["id"] == d["task"]["id"]][0]
    assert derived["status"] == "open"


def test_reopen_via_related_claims(tmp_path: Path):
    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Was Host A compromised?\n",
        encoding="utf-8",
    )
    r = reconcile_case_md(case, persist=True)
    tid = r["added"][0]
    from core.claim_graph import add_claim
    cid = add_claim(case, "Host A was compromised.", confidence="LIKELY",
                    enforce_validation=False)["node_id"]
    assert update_task(case, tid, status="answered",
                       related_claim_ids=[cid])["success"]
    out = reopen_tasks_for_claims(case, [cid])
    assert tid in out["reopened"]
    assert load_tasks(case)["tasks"][0]["status"] == "reopened"


def test_link_claim_to_sole_open_task(tmp_path: Path):
    from core.investigation_tasks import link_claim_to_tasks

    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Was workstation WS01 compromised?\n",
        encoding="utf-8",
    )
    r = reconcile_case_md(case, persist=True)
    tid = r["added"][0]
    out = link_claim_to_tasks(
        case,
        "C0001",
        statement="Suspicious PowerShell on unrelated host",
        host="OTHER",
    )
    # Sole open inbox task always receives the claim.
    assert tid in out["linked"]
    t = load_tasks(case)["tasks"][0]
    assert "C0001" in t["related_claim_ids"]
    assert t["status"] == "in_progress"


def test_link_claim_token_overlap_not_wrong_task(tmp_path: Path):
    from core.investigation_tasks import link_claim_to_tasks

    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n"
        "- Investigate lateral movement from user01\n"
        "- Review VPN authentication failures\n",
        encoding="utf-8",
    )
    reconcile_case_md(case, persist=True)
    out = link_claim_to_tasks(
        case,
        "C0009",
        statement="user01 authenticated to FILESRV02 via RDP (lateral movement)",
        host="FILESRV02",
    )
    store = load_tasks(case)
    by_id = {t["id"]: t for t in store["tasks"]}
    linked = set(out["linked"])
    assert linked
    # Must hit the lateral/user01 task; VPN-only task should stay unlinked
    # unless overlap is strong enough (vpn not in statement).
    for tid in linked:
        assert "lateral" in by_id[tid]["text"].casefold() or "user01" in by_id[tid]["text"].casefold()
    vpn = [t for t in store["tasks"] if "VPN" in t["text"]][0]
    assert "C0009" not in (vpn.get("related_claim_ids") or [])


def test_plane_a_reconciles_tasks(tmp_path: Path):
    case = tmp_path / "case"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    (ev / "a.txt").write_bytes(b"x")
    (case / "CASE.md").write_text(
        "**Case ID** Demo\n\n## Investigation Requests\n\n"
        "- Determine compromise\n",
        encoding="utf-8",
    )
    result = plane_a_scan(case, persist=True)
    assert result["success"]
    tr = result.get("task_reconcile") or {}
    assert tr.get("counts", {}).get("added", 0) >= 1
    assert (case / ".atlas" / "investigation_tasks.json").is_file()
    assert (case / ".atlas" / "investigation_plan.json").is_file()
    plan = result.get("investigation_plan") or {}
    assert plan.get("steps")
    assert (case / ".atlas" / "rerun_brief.md").is_file()
    brief = (case / ".atlas" / "rerun_brief.md").read_text(encoding="utf-8")
    assert "Investigation Tasks" in brief
    assert "Investigation Plan" in brief


def test_scaffold_creates_tasks_file(tmp_path: Path):
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** X\n", encoding="utf-8")
    r = ensure_atlas_scaffold(case, case_id="X")
    assert "investigation_tasks.json" in r["created"]
    assert (case / ".atlas" / "investigation_tasks.json").is_file()


def _seed_two_requests(case: Path) -> dict:
    """Case with two parsed requests, one of them in_progress with a claim."""
    (case / "evidence").mkdir(parents=True, exist_ok=True)
    (case / "CASE.md").write_text(
        "**Case ID:** PROBE-1\n\n## Investigation Requests\n\n"
        "- Determine whether the workstation was compromised.\n"
        "- Identify the initial access vector.\n",
        encoding="utf-8")
    reconcile_case_md(case, persist=True)
    store = load_tasks(case)
    store["tasks"][0]["status"] = "in_progress"
    store["tasks"][0]["related_claim_ids"] = ["CL-1", "CL-2"]
    (case / ".atlas" / "investigation_tasks.json").write_text(
        json.dumps(store), encoding="utf-8")
    add_derived_task(case, "revisit the registry hive when the image lands")
    return load_tasks(case)


def test_unparsable_case_md_does_not_wipe_the_queue(tmp_path: Path):
    """Nothing parsed is not "every line removed".

    An empty, absent, renamed-heading or prose-only CASE.md yields zero
    requests. Dropping on that wiped the whole actionable queue — in_progress
    tasks and their related_claim_ids included — on the hot path of every run
    (agent/cli.py -> plane_a_scan -> reconcile_case_md), and said nothing.
    A brief written as prose parses to zero requests, so this path is an
    ordinary one.
    """
    for name, body in (
            ("empty", ""),
            ("prose_only", "**Case ID:** PROBE-1\n\n## Scope\n\nOne host.\n"),
            ("absent", None),
    ):
        case = tmp_path / name
        case.mkdir()
        before = _seed_two_requests(case)
        if body is None:
            (case / "CASE.md").unlink()
        else:
            (case / "CASE.md").write_text(body, encoding="utf-8")

        reconcile_case_md(case, persist=True)
        after = load_tasks(case)

        assert [t["status"] for t in after["tasks"]] == \
               [t["status"] for t in before["tasks"]], name
        assert not [t for t in after["tasks"] if t["status"] == "dropped"], name
        kept = next(t for t in after["tasks"] if t["status"] == "in_progress")
        assert kept["related_claim_ids"] == ["CL-1", "CL-2"], name


def test_removed_request_line_still_drops_its_task(tmp_path: Path):
    """The guard must not disable the rule it guards: a line that really was
    removed still drops exactly its own task, and only that one."""
    case = tmp_path / "case"
    case.mkdir()
    _seed_two_requests(case)
    (case / "CASE.md").write_text(
        "**Case ID:** PROBE-1\n\n## Investigation Requests\n\n"
        "- Determine whether the workstation was compromised.\n",
        encoding="utf-8")

    r = reconcile_case_md(case, persist=True)
    after = load_tasks(case)
    dropped = [t for t in after["tasks"] if t["status"] == "dropped"]
    assert len(dropped) == 1, r
    assert "initial access vector" in dropped[0]["text"]


def test_add_derived_task_applies_the_prefix_itself(tmp_path: Path):
    """The prefix is what stops reconcile from dropping a derived task, so it
    cannot depend on each caller remembering it — only derived_revisit.py did."""
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID:** P\n", encoding="utf-8")

    plain = add_derived_task(case, "no prefix from the caller")["task"]["text"]
    assert plain.lower().startswith(DERIVED_PREFIX)

    already = add_derived_task(
        case, f"{DERIVED_PREFIX} already prefixed")["task"]["text"]
    assert already.lower().count(DERIVED_PREFIX) == 1


def test_a_supersession_carries_the_task_link_to_the_successor(tmp_path: Path):
    """A question answered by a belief stays answered by the belief that
    replaces it; without the carried link the task was reopened at close-out
    and the report read "not answered" beside a current finding."""
    from core import claim_graph as cg
    from core.investigation_tasks import carry_links_on_supersede, repair_unsupported_answers
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Malware: whether the machine carries a trojan\n",
        encoding="utf-8")
    tid = reconcile_case_md(case, persist=True)["added"][0]
    old = cg.add_claim(case, statement="ClamAV flagged a trojan in helper.dll on the machine",
                       confidence="LIKELY")["node_id"]
    new = cg.add_claim(case, statement="ClamAV flagged the trojan Win.Trojan.Example-9 in helper.dll on the machine",
                       confidence="LIKELY")["node_id"]
    assert update_task(case, tid, status="answered", related_claim_ids=[old])["success"]
    assert cg.supersede(case, old, new, reason="re-recorded with the signature name")["success"]
    task = {t["id"]: t for t in load_tasks(case)["tasks"]}[tid]
    assert new in task["related_claim_ids"] and old in task["related_claim_ids"]
    assert task["status"] == "answered"
    assert repair_unsupported_answers(case) == []
    # idempotent and inert for unrelated ids
    assert carry_links_on_supersede(case, old, new) == []
    assert carry_links_on_supersede(case, "C9999", new) == []


class TestRequestItems:
    """A request wrapped over several lines is one request; its nested
    bullets are its children; its first physical line is remembered so a
    store written by an earlier reader is recognised."""

    MD = (
        "# Case: X\n\n**Case ID:** X\n\n## Investigation Requests\n\n"
        "1. **Device and system baseline** — image integrity, operating system, install date, timezone,\n"
        "   registered owner, computer name, primary domain, last shutdown, accounts.\n"
        "2. **Who used it** — main and last user.\n"
        "   - the account that binds to the named person\n"
        "   - the artefact that shows it,\n"
        "     across two lines\n"
        "3. Malware — whether the machine carries viruses.\n"
        "lazy continuation of the third item\n"
        "\n"
        "Prose after a blank line is guidance, not a request.\n"
        "4. The last one.\n"
        "## Why this case\n"
        "- not a request\n"
    )

    def test_wrapped_items_children_and_first_lines(self):
        items = parse_case_request_items(self.MD)
        texts = [i["text"] for i in items]
        assert texts == [
            "Device and system baseline — image integrity, operating system, install date, timezone, "
            "registered owner, computer name, primary domain, last shutdown, accounts.",
            "Who used it — main and last user.",
            "Malware — whether the machine carries viruses. lazy continuation of the third item",
            "The last one.",
        ]
        assert items[0]["first_line"] == ("Device and system baseline — image integrity, operating system, "
                                          "install date, timezone,")
        assert items[1]["children"] == ["the account that binds to the named person",
                                        "the artefact that shows it, across two lines"]
        assert items[2]["children"] == [] and items[3]["first_line"] == "The last one."
        assert parse_case_requests(self.MD) == texts

    @pytest.mark.skipif(not DEVTOOLS_SHIPPED, reason=NO_DEV_DATA)
    def test_the_benchmark_briefs_parse_whole(self):
        import glob
        root = Path(__file__).resolve().parents[2]
        wrapped = 0
        for f in sorted(glob.glob(str(root / "benchmarks" / "*" / "CASE.md"))):
            for item in parse_case_request_items(Path(f).read_text(encoding="utf-8")):
                assert not item["text"].rstrip().endswith((",", "—", "-", " and", " plus", " or")), (f, item["text"])
                wrapped += item["first_line"] != item["text"]
        assert wrapped >= 1

    def test_the_demo_briefs_parse_whole(self):
        import glob
        root = Path(__file__).resolve().parents[2]
        # Briefs without wrapped items read as written: their first
        # line is their text.
        for f in sorted(glob.glob(str(root / "demo-cases" / "*" / "CASE.md"))) + [str(root / "case-template" / "CASE.md")]:
            for item in parse_case_request_items(Path(f).read_text(encoding="utf-8")):
                assert item["first_line"] == item["text"], (f, item["text"])


class TestTruncatedTaskMigration:
    def _store(self, case, text, status, claims):
        (case / ".atlas").mkdir(parents=True, exist_ok=True)
        store = {"schema_version": "1.0", "case_id": "X", "next_id": 2, "tasks": [{
            "id": "task-0001", "text": text, "status": status, "related_claim_ids": claims,
            "superseded_by": "", "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"}]}
        (case / ".atlas" / "investigation_tasks.json").write_text(json.dumps(store), encoding="utf-8")

    def test_a_task_holding_the_first_line_takes_the_whole_request(self, tmp_path: Path):
        case = tmp_path / "X"
        case.mkdir()
        (case / "CASE.md").write_text(
            "**Case ID:** X\n\n## Investigation Requests\n"
            "1. **Baseline** — operating system, install date, timezone,\n"
            "   registered owner and accounts.\n", encoding="utf-8")
        self._store(case, "Baseline — operating system, install date, timezone,", "answered", ["C0003"])
        r = reconcile_case_md(case)
        assert r["extended"] == ["task-0001"] and r["added"] == [] and r["dropped"] == []
        tasks = r["tasks"]
        assert len(tasks) == 1
        t = tasks[0]
        assert t["text"] == "Baseline — operating system, install date, timezone, registered owner and accounts."
        assert t["status"] == "reopened" and t["related_claim_ids"] == ["C0003"]
        assert "text extended" in t["note"]
        # Idempotent: the next reconcile matches by fingerprint.
        r2 = reconcile_case_md(case)
        assert r2["extended"] == [] and r2["matched"] == ["task-0001"]

    def test_an_open_task_is_extended_without_reopening(self, tmp_path: Path):
        case = tmp_path / "X"
        case.mkdir()
        (case / "CASE.md").write_text(
            "**Case ID:** X\n\n## Investigation Requests\n"
            "- USB key — recover content by carving; two carrier images hold\n"
            "  steganographic payloads.\n", encoding="utf-8")
        self._store(case, "USB key — recover content by carving; two carrier images hold", "in_progress", [])
        r = reconcile_case_md(case)
        assert r["extended"] == ["task-0001"] and r["tasks"][0]["status"] in ("open", "in_progress")
        assert [p["text"] for p in r["tasks"][0]["parts"]]

    def test_a_reworded_request_is_a_new_task_as_before(self, tmp_path: Path):
        case = tmp_path / "X"
        case.mkdir()
        (case / "CASE.md").write_text(
            "**Case ID:** X\n\n## Investigation Requests\n- Determine the initial access vector.\n",
            encoding="utf-8")
        self._store(case, "Determine the initial access", "open", [])
        r = reconcile_case_md(case)
        assert r["extended"] == [] and len(r["added"]) == 1


def test_an_observation_answers_a_baseline_part_and_a_bare_part_value_is_refused(tmp_path):
    """A reading from the system baseline states a fact as well as a claim
    does: it answers the part whose value it carries. A value typed into
    the part update is not evidence and is refused with the shape to use."""
    from core.claim_graph import add_observation
    from core.investigation_tasks import load_tasks, reconcile_case_md, update_task
    case = tmp_path / "CASE"
    (case / ".atlas").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID:** CASE\n\n## Investigation Requests\n"
                                  "- Baseline — the operating system and the time zone of the workstation.\n", encoding="utf-8")
    reconcile_case_md(case)
    tid = load_tasks(case)["tasks"][0]["id"]
    o1 = add_observation(case, "The installation on ws01 runs Windows 10 Pro (10.0 build 19045 Professional).",
                         confidence="CONFIRMED", host="WS01", attrs={"baseline": "os.product"})["node_id"]
    o2 = add_observation(case, "The time zone of the installation on ws01 is W. Europe Standard Time (TimeZoneKeyName, bias -60 minutes).",
                         confidence="CONFIRMED", host="WS01", attrs={"baseline": "time.zone"})["node_id"]
    r = update_task(case, tid, status="answered", related_claim_ids=[o1, o2])
    assert r.get("success"), r
    task = r["task"]
    assert task["status"] == "answered"
    assert {p["status"] for p in task["parts"]} == {"answered"}
    bad = update_task(case, tid, status="answered", related_claim_ids=[o1, o2], parts={"p1": "Windows 10 Pro"})
    assert not bad.get("success") and "takes an object" in bad["error"]


def test_answer_candidates_list_conclusions_then_claims_before_readings(tmp_path):
    """A baseline's CONFIRMED readings never push the analyst's own beliefs
    off the candidate list offered back on a refused close."""
    from core.claim_graph import add_claim, add_observation
    from core.investigation_tasks import answer_candidates
    case = tmp_path / "CASE"
    (case / ".atlas").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID:** CASE\n", encoding="utf-8")
    for n in range(10):
        add_observation(case, f"The reading {n} of the installation on ws01 is value {n}.",
                        confidence="CONFIRMED", host="WS01", attrs={"baseline": f"x.{n}"})
    claims = [add_claim(case, f"Claim {n} about ws01 was established by evidence.", confidence="LIKELY", host="WS01")["node_id"]
              for n in range(3)]
    offered = answer_candidates(case)
    assert len(offered) == 8
    assert all(any(line.startswith(c + " ") for line in offered[:3]) for c in claims)
    assert all("The reading" in line for line in offered[3:])


def test_a_refused_close_offers_the_reading_that_answers_the_open_part_first(tmp_path):
    """The candidates on a refusal lead with the beliefs that carry a value the
    open parts ask for, whatever their kind, so a baseline reading reaches the
    model even when claims would fill the list."""
    from core.claim_graph import add_claim, add_observation
    from core.investigation_tasks import answer_candidates, load_tasks, reconcile_case_md, update_task
    case = tmp_path / "CASE"
    (case / ".atlas").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID:** CASE\n\n## Investigation Requests\n"
                                  "- Baseline — both operating systems of the estate.\n", encoding="utf-8")
    reconcile_case_md(case)
    tid = load_tasks(case)["tasks"][0]["id"]
    for n in range(9):
        add_claim(case, f"Claim {n} about ws01 was established by evidence.", confidence="CONFIRMED", host="WS01")
    o = add_observation(case, "The operating system of the installation on ws01 is Windows 10 Pro (10.0 build 19045).",
                        confidence="CONFIRMED", host="WS01", attrs={"baseline": "os.product"})["node_id"]
    parts = load_tasks(case)["tasks"][0]["parts"]
    offered = answer_candidates(case, parts=parts)
    assert offered and offered[0].startswith(o + " ")
    r = update_task(case, tid, status="answered", related_claim_ids=[])
    assert not r.get("success") and r["candidates"][0].startswith(o + " ")
    r = update_task(case, tid, status="answered", related_claim_ids=[o])
    assert r.get("success") and r["task"]["parts"][0]["status"] == "answered"


_FENCED_BRIEF = (
    "# Case CASE-A\n"
    "\n"
    "## What you already know\n"
    "\n"
    "- CORP-DC01 is the admin jump host.\n"
    "\n"
    "```\n"
    "2031-03-04 10:02 logon jane.doe CORP-DC01\n"
    "\n"
    "## Investigation Requests\n"
    "\n"
    "1. Which account logged on to CORP-DC01?\n"
    "2. When did the copy start?\n"
)


class TestUnclosedFence:
    """A block that never closes hides everything after it from the parsers;
    the helper says where, and what it hides."""

    def test_names_the_opening_line_and_what_it_hides(self):
        from core.investigation_tasks import unclosed_fence
        fence = unclosed_fence(_FENCED_BRIEF)
        assert fence["line"] == 7
        assert "## Investigation Requests" in fence["hidden"]
        assert fence["hidden_requests"] == 2

    def test_closed_blocks_and_fences_in_comments_are_quiet(self):
        from core.investigation_tasks import unclosed_fence
        closed = _FENCED_BRIEF.replace("CORP-DC01\n\n## Inv", "CORP-DC01\n```\n\n## Inv")
        assert unclosed_fence(closed) is None
        assert unclosed_fence("<!--\n```\n-->\n## Investigation Requests\n\n- One?\n") is None

    def test_numbering_is_the_files_own_across_a_comment(self):
        from core.investigation_tasks import unclosed_fence
        brief = "<!-- a two-line\n     comment -->\n```\n## Investigation Requests\n- One?\n"
        assert unclosed_fence(brief)["line"] == 3

    def test_a_trailing_paste_that_hides_nothing_is_quiet(self):
        from core.investigation_tasks import unclosed_fence
        assert unclosed_fence("## Investigation Requests\n\n- One?\n\n```\nlog line\nlog line\n") is None

    def test_reconcile_drops_no_task_the_block_hides(self, tmp_path: Path):
        case = tmp_path / "case"
        case.mkdir()
        three = ("## Investigation Requests\n\n- Which account logged on to CORP-DC01?\n"
                 "- When did the copy start?\n- Was data sent to 203.0.113.9?\n")
        (case / "CASE.md").write_text(three, encoding="utf-8")
        reconcile_case_md(case, persist=True)
        hidden = three.replace("- When did", "```\n- When did")
        (case / "CASE.md").write_text(hidden, encoding="utf-8")
        r = reconcile_case_md(case, persist=True)
        assert r["dropped"] == [] and r["drops_skipped"] is True
        assert r["unclosed_fence"]["line"] == 4
        assert all(t["status"] != "dropped" for t in load_tasks(case)["tasks"])


class TestThematicBreaksAreNoRequests:
    """A CommonMark thematic break (`* * *`, `- - -`, `***`) separates; it is never a request, a request's
    continuation or a child, at any indentation."""

    BRIEF = ("**Case ID:** CASE-A\n\n## Investigation Requests\n"
             "- Was data taken from CORP-FS01?\n* * *\n"
             "- Who logged on to CORP-WS01?\n  - over which protocol\n- - -\n"
             "1. Which tools ran?\n    * * *\n"
             "* item with a star\n\t- - -\n***\n")

    def test_breaks_create_no_request_and_end_the_item_above(self):
        assert parse_case_requests(self.BRIEF) == [
            "Was data taken from CORP-FS01?", "Who logged on to CORP-WS01?", "Which tools ran?",
            "item with a star"]
        children = {i["text"]: i["children"] for i in parse_case_request_items(self.BRIEF)}
        assert children["Who logged on to CORP-WS01?"] == ["over which protocol"]
        assert children["Which tools ran?"] == []

    def test_a_reconciled_brief_holds_no_break_task(self, tmp_path):
        case = tmp_path / "CASE-A"
        (case / ".atlas").mkdir(parents=True)
        (case / "CASE.md").write_text(self.BRIEF, encoding="utf-8")
        reconcile_case_md(case)
        texts = [t["text"] for t in load_tasks(case)["tasks"]]
        assert "* *" not in texts and "- -" not in texts and len(texts) == 4


def test_link_claim_never_touches_the_parts(tmp_path: Path):
    """Record-time linking links the belief and leaves the parts exactly as
    they were: only the analyst's own update closes a part."""
    import copy
    from core.claim_graph import add_claim
    from core.investigation_tasks import link_claim_to_tasks

    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Which host was compromised first and when?\n",
        encoding="utf-8",
    )
    tid = reconcile_case_md(case, persist=True)["added"][0]
    before = copy.deepcopy(load_tasks(case)["tasks"][0]["parts"])
    assert before and all(p["status"] == "open" for p in before)
    cid = add_claim(case, "Host CORP-WS07 was compromised first, on 2031-02-04 10:00 UTC, by a phishing attachment.",
                    confidence="LIKELY", host="CORP-WS07")["node_id"]
    out = link_claim_to_tasks(case, cid, statement="Host CORP-WS07 was compromised first, on 2031-02-04 10:00 UTC, "
                                                   "by a phishing attachment.", host="CORP-WS07")
    assert tid in out["linked"]
    t = load_tasks(case)["tasks"][0]
    assert t["status"] == "in_progress" and t["related_claim_ids"] == [cid]
    assert t["parts"] == before


def test_a_parts_only_close_of_a_host_gate_limits_the_hosts_other_parts_in_the_same_call(tmp_path: Path):
    """A per-host gate answered "not affected" by an absence finding is an
    analyst binding; the host's other standard parts are limited in the same
    update, however the call is shaped."""
    from core import request_parts as rp
    from core.claim_graph import add_claim
    from core.investigation_tasks import save_tasks, update_task

    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- What happened on the hosts?\n", encoding="utf-8")
    reconcile_case_md(case, persist=True)
    store = load_tasks(case)
    t = store["tasks"][0]
    std = rp.standard_parts(t["text"], ["CORP-WS01", "CORP-WS02"])
    t["parts"] = [p for p in t.get("parts") or [] if p.get("kind") == "umbrella"] + std
    save_tasks(case, store)
    gate = next(p for p in std if p.get("gate") and p.get("host") == "CORP-WS02")
    cid = add_claim(case, "No evidence of attacker activity was found on CORP-WS02: its event logs, prefetch "
                          "and registry show no intrusion.", confidence="LIKELY", host="CORP-WS02")["node_id"]
    r = update_task(case, t["id"], parts={gate["id"]: {"claim_ids": [cid]}})
    assert r.get("success"), r
    after = load_tasks(case)["tasks"][0]["parts"]
    ws02 = [p for p in after if p.get("host") == "CORP-WS02"]
    assert next(p for p in ws02 if p.get("gate"))["status"] == "answered"
    assert all(p["status"] == "limited" for p in ws02 if not p.get("gate"))
    assert all(p["status"] == "open" for p in after if p.get("host") == "CORP-WS01")


def test_a_progress_note_closes_nothing_and_only_the_links_a_close_names_mark_a_part(tmp_path: Path, monkeypatch):
    """A status-only progress note leaves the parts as they are, record-time
    links or not. A close may answer a part from the task's stored links;
    that part carries no ``closed_by``. The close that names the belief
    marks the part the analyst's. (The old path: ATLAS_PART_GATE_STRUCTURAL
    off.)"""
    from core.claim_graph import add_claim
    from core.investigation_tasks import link_claim_to_tasks, update_task
    monkeypatch.setenv("ATLAS_PART_GATE_STRUCTURAL", "0")

    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Which host was compromised first?\n",
        encoding="utf-8",
    )
    tid = reconcile_case_md(case, persist=True)["added"][0]
    cid = add_claim(case, "Host CORP-WS07 was compromised first, by a phishing attachment.",
                    confidence="LIKELY", host="CORP-WS07")["node_id"]
    link_claim_to_tasks(case, cid, statement="Host CORP-WS07 was compromised first, by a phishing attachment.",
                        host="CORP-WS07")
    assert all(p["status"] == "open" for p in load_tasks(case)["tasks"][0]["parts"])

    update_task(case, tid, status="in_progress")
    t = load_tasks(case)["tasks"][0]
    assert t["status"] == "in_progress" and all(p["status"] == "open" for p in t["parts"])

    update_task(case, tid, status="answered")
    parts = load_tasks(case)["tasks"][0]["parts"]
    assert [p["status"] for p in parts] == ["answered"] and parts[0]["claim_ids"] == [cid]
    assert "closed_by" not in parts[0]

    update_task(case, tid, status="answered", related_claim_ids=[cid])
    t = load_tasks(case)["tasks"][0]
    assert t["related_claim_ids"] == [cid] and t["parts"][0]["closed_by"] == "analyst"


class TestTheBriefsMainQuestionIsTracked:
    """A brief's CASE_QUESTION marker is Atlas's objective line. It is a
    tracked task beside the requests, and the only one when the brief lists
    no requests; a request that repeats it is not doubled."""

    QUESTION = ("Establish who copied the payroll export from CORP-WS01 and where it went, "
                "and whether jane.doe's account was used.")

    def _case(self, tmp_path: Path, md: str) -> Path:
        case = tmp_path / "CASE-A"
        case.mkdir(parents=True)
        (case / "CASE.md").write_text(md, encoding="utf-8")
        return case

    def test_a_bare_brief_with_only_the_marker_gets_one_task(self, tmp_path: Path):
        case = self._case(tmp_path, f"# Case: CASE-A\n\n## CASE_QUESTION: {self.QUESTION}\n")
        r = reconcile_case_md(case, persist=True)
        assert [t["text"] for t in r["tasks"]] == [self.QUESTION]

    def test_the_marker_leads_the_requests_in_every_written_form(self, tmp_path: Path):
        for i, line in enumerate((f"CASE_QUESTION: {self.QUESTION}",
                                  f"**CASE_QUESTION:** {self.QUESTION}",
                                  f"**CASE_QUESTION: {self.QUESTION}**")):
            case = self._case(tmp_path / str(i), (
                "# Case: CASE-A\n\n### Case Question\n\n" + line + "\n\n"
                "## Investigation Requests\n\n"
                "1. When was the export first opened?\n"
                "2. Which account ran the copy?\n"))
            r = reconcile_case_md(case, persist=True)
            assert [t["text"] for t in r["tasks"]] == [
                self.QUESTION, "When was the export first opened?", "Which account ran the copy?"], line

    def test_beside_requests_the_question_is_one_obligation_a_bare_one_is_split(self, tmp_path: Path):
        reqs = "## Investigation Requests\n\n1. When was the export first opened?\n"
        beside = reconcile_case_md(self._case(tmp_path / "a", f"CASE_QUESTION: {self.QUESTION}\n\n{reqs}"),
                                   persist=True)["tasks"][0]
        assert [(p["text"], p["type"]) for p in beside["parts"]] == [(self.QUESTION, "narrative")]
        bare = reconcile_case_md(self._case(tmp_path / "b", f"CASE_QUESTION: {self.QUESTION}\n"),
                                 persist=True)["tasks"][0]
        assert len(bare["parts"]) > 1
        # The brief gains requests later: the question becomes one part.
        (tmp_path / "b" / "CASE-A" / "CASE.md").write_text(f"CASE_QUESTION: {self.QUESTION}\n\n{reqs}",
                                                          encoding="utf-8")
        again = reconcile_case_md(tmp_path / "b" / "CASE-A", persist=True)["tasks"]
        assert len(again[0]["parts"]) == 1 and len(again) == 2

    def test_the_whole_question_is_answered_by_a_belief_that_speaks_to_it(self):
        from core import request_parts as rp
        t = {"text": self.QUESTION, "status": "open", "related_claim_ids": []}
        rp.ensure_parts(t, whole=True)
        node = {"id": "C1", "kind": "claim", "status": "active", "host": "CORP-WS01",
                "statement": ("jane.doe copied the payroll export from CORP-WS01 to a USB drive on "
                              "2031-03-04; her account was used for the copy.")}
        assert rp.assign(t, {"C1": node}, ["C1"], lenient=True) == ["p1"]

    def test_a_question_the_requests_repeat_is_one_task(self, tmp_path: Path):
        case = self._case(tmp_path, (
            f"## CASE_QUESTION: {self.QUESTION}\n\n## Investigation Requests\n\n- {self.QUESTION}\n"))
        assert len(reconcile_case_md(case, persist=True)["tasks"]) == 1

    def test_a_brief_without_a_store_still_names_its_question_as_the_objective(self, tmp_path: Path):
        from types import SimpleNamespace
        from agent.cli import _resolve_case_question
        case = self._case(tmp_path, f"## CASE_QUESTION: {self.QUESTION}\n")
        assert _resolve_case_question(SimpleNamespace(question=None), case) == self.QUESTION


def test_a_refused_part_refuses_the_whole_call_and_prints_the_saved_state(tmp_path: Path):
    """Parts are one call, one state: a part refused refuses the whole
    update, nothing is recorded, the refusal says per part what would have
    held, and the parts it prints are the saved ones (never the parts
    applied in memory before the refusal)."""
    from core import request_parts as rp
    from core.investigation_tasks import save_tasks, update_task

    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- What happened on the hosts?\n\nThe mail server is out of scope.\n",
        encoding="utf-8")
    reconcile_case_md(case, persist=True)
    store = load_tasks(case)
    t = store["tasks"][0]
    std = rp.standard_parts(t["text"], ["CORP-WS01"])
    t["parts"] = [p for p in t.get("parts") or [] if p.get("kind") == "umbrella"] + std
    save_tasks(case, store)
    ids = [p["id"] for p in std if not p.get("gate")][:3]
    assert len(ids) == 3
    held = {"limitation": {"basis": "out_of_scope",
                           "reason": "the brief excludes the mail server, the only source for this part"}}
    r = update_task(case, t["id"], parts={ids[0]: held, ids[1]: held,
                                         ids[2]: {"limitation": {"basis": "guessed", "reason": "x" * 30}}})
    assert not r.get("success") and r.get("gate") == "task_part_limitation", r
    assert r["verdicts"] == [f"{ids[0]} would hold", f"{ids[1]} would hold", f"{ids[2]} refused"]
    assert "Nothing was recorded" in r["error"]
    assert not any("not determined" in line for line in r["parts"])
    after = {p["id"]: p for p in load_tasks(case)["tasks"][0]["parts"]}
    assert all(after[i]["status"] == "open" and not after[i].get("limitation") for i in ids)
    ok = update_task(case, t["id"], parts={ids[0]: held, ids[1]: held})
    assert ok.get("success"), ok
    after = {p["id"]: p for p in load_tasks(case)["tasks"][0]["parts"]}
    assert after[ids[0]]["status"] == "limited" and after[ids[1]]["status"] == "limited"


def test_capitals_in_a_limitation_reason_are_sources_only_when_the_case_knows_them(tmp_path: Path):
    """An acronym and a binary's name written in capitals are words of the
    reason, not sources the cited calls must name: a successful read of
    the log the reason describes holds the examined limitation."""
    from core import request_parts as rp
    from core.execution_log import log
    from core.investigation_tasks import save_tasks, update_task

    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text("## Investigation Requests\n\n- What happened on the hosts?\n", encoding="utf-8")
    reconcile_case_md(case, persist=True)
    store = load_tasks(case)
    t = store["tasks"][0]
    std = rp.standard_parts(t["text"], ["CORP-WS01"])
    t["parts"] = [p for p in t.get("parts") or [] if p.get("kind") == "umbrella"] + std
    save_tasks(case, store)
    pid = next(p["id"] for p in std if not p.get("gate"))
    cids = []
    for host in ("CORP-WS01", "CORP-DC01"):
        cid = log.record_tool_call(
            f"<py>:evtx_filter evidence/{host}/Windows/System32/winevt/Logs/System.evtx event_ids=[7045]",
            True, False, 0, 0, stdout_excerpt='{"success": true, "matches_found": 2, "events": ["<Event/>"]}')
        log.annotate_tool_call(cid, mcp_tool="misc_evtx_filter")
        cids.append(cid)
    reason = ("Service installs (EID 7045) were read on both hosts. Only the SVCKIT installs on the "
              "workstation were found, transient execution rather than persistence.")
    r = update_task(case, t["id"], parts={pid: {"limitation": {"basis": "examined", "reason": reason,
                                                               "call_ids": cids}}})
    assert r.get("success"), r
    part = next(p for p in load_tasks(case)["tasks"][0]["parts"] if p["id"] == pid)
    assert part["status"] == "limited" and part["limitation"]["basis"] == "examined"


def test_a_refused_close_prints_the_saved_parts_and_records_nothing(tmp_path: Path):
    """A close refused after the loop (open parts remain) is the same
    refusal as one inside it: the parts printed are the saved ones, and
    the open list is the one the call would have produced."""
    from core import request_parts as rp
    from core.investigation_tasks import save_tasks, update_task

    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- What happened on the hosts?\n\nThe mail server is out of scope.\n",
        encoding="utf-8")
    reconcile_case_md(case, persist=True)
    store = load_tasks(case)
    t = store["tasks"][0]
    std = rp.standard_parts(t["text"], ["CORP-WS01"])
    t["parts"] = [p for p in t.get("parts") or [] if p.get("kind") == "umbrella"] + std
    save_tasks(case, store)
    pid = next(p["id"] for p in std if not p.get("gate"))
    r = update_task(case, t["id"], status="blocked_missing_evidence", parts={pid: {"limitation": {
        "basis": "out_of_scope", "reason": "the brief excludes the mail server, the only source for this part"}}})
    assert not r.get("success") and r.get("gate") == "task_parts_open" and "Nothing was recorded" in r["error"]
    assert not any("not determined" in line for line in r["parts"])
    assert f"{pid} would hold; the status 'blocked_missing_evidence' is refused" in r["error"]
    assert "the refused one corrected" not in r["error"] and r["error"].count("Nothing was recorded") == 1
    assert next(p for p in load_tasks(case)["tasks"][0]["parts"] if p["id"] == pid)["status"] == "open"


def test_capitals_name_a_source_for_an_absence_and_a_present_file_is_not_absent(case, monkeypatch):
    """For source_absent every capitals word is searched for in the case's
    index (the name stem): a binary the listing holds cannot be called
    absent, whatever its spelling. The filter that keeps only known
    artefact names applies where the cited calls must name the source
    (examined, unreadable), never here."""
    from core import request_parts as rp
    from core.investigation_tasks import save_tasks, update_task
    from tests.core.test_contents_index import _body, _build, _image, _links, _plan

    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": [
        _body("Windows/System32/winevt/Logs/Security.evtx", "200-128-1", 70000),
        _body("Windows/SVCKIT.exe", "300-128-1", 4096)]})
    (case / "CASE.md").write_text("## Investigation Requests\n\n- What happened on the hosts?\n", encoding="utf-8")
    reconcile_case_md(case, persist=True)
    store = load_tasks(case)
    t = store["tasks"][0]
    std = rp.standard_parts(t["text"], ["CORP-WS01"])
    t["parts"] = [p for p in t.get("parts") or [] if p.get("kind") == "umbrella"] + std
    save_tasks(case, store)
    pid = next(p["id"] for p in std if not p.get("gate"))
    r = update_task(case, t["id"], parts={pid: {"limitation": {
        "basis": "source_absent", "reason": "SVCKIT is not present on this workstation, no service binary was found"}}})
    assert not r.get("success") and "is present in this case" in r["error"], r


def test_an_artefact_written_in_capitals_is_still_the_source_the_cited_read_must_name(case, monkeypatch):
    """A file name in capitals is an artefact token first: an examined
    limitation naming SYSTEM.EVTX while citing a read of another log is
    refused, as it was before the capitals rule."""
    from core import request_parts as rp
    from core.execution_log import log
    from core.investigation_tasks import save_tasks, update_task
    (case / "CASE.md").write_text("## Investigation Requests\n\n- What happened on the hosts?\n", encoding="utf-8")
    reconcile_case_md(case, persist=True)
    store = load_tasks(case)
    t = store["tasks"][0]
    std = rp.standard_parts(t["text"], ["CORP-WS01"])
    t["parts"] = [p for p in t.get("parts") or [] if p.get("kind") == "umbrella"] + std
    save_tasks(case, store)
    pid = next(p["id"] for p in std if not p.get("gate"))
    cid = log.record_tool_call("<py>:evtx_filter evidence/CORP-WS01/Windows/System32/winevt/Logs/Security.evtx event_ids=[4624]",
                               True, False, 0, 0, stdout_excerpt='{"success": true, "matches_found": 2, "events": ["<Event/>"]}')
    log.annotate_tool_call(cid, mcp_tool="misc_evtx_filter")
    r = update_task(case, t["id"], parts={pid: {"limitation": {
        "basis": "examined", "reason": "SYSTEM.EVTX was read with the 7045 filter and shows no service installs in the window.",
        "call_ids": [cid]}}})
    assert not r.get("success") and "does not name the source" in r["error"]
