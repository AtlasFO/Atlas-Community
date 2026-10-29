"""The Brief tab saves with the version of the brief it read. A save from a
tab whose brief changed since (another user's save, a question added in the
start dialog, a rerun's fact) is answered 409 with the current text and
changes nothing; a save without a version is refused. Saving the brief keeps
the task store's case id on the brief's own Case ID line, the id a run
writes, also for a case whose folder is named otherwise and after a rename.
Invented cases on a scratch server."""
from __future__ import annotations

import http.client
import json

import pytest

from core import case_knowledge
from core.investigation_tasks import load_tasks
from dashboard import case_admin
from tests.tools.test_dashboard import standalone_server  # noqa: F401


def _call(server, method, route, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", server["port"], timeout=10)
    conn.request(method, f"/_dashboard/api/{route}",
                 body=json.dumps(body).encode() if body is not None else None,
                 headers={"Content-Type": "application/json"})
    try:
        resp = conn.getresponse()
        return resp.status, json.loads(resp.read() or b"{}")
    finally:
        conn.close()


def _read(server, case):
    status, data = _call(server, "GET", f"case/case_md?case={case}")
    assert status == 200, data
    return data


def _save(server, case, content, version):
    return _call(server, "POST", "case/case_md/save",
                 {"case": case, "content": content, "version": version})


@pytest.fixture
def srv(standalone_server):
    assert _call(standalone_server, "POST", "case/create",
                 {"case_id": "CASE-A", "requests": ["What ran on CORP-WS01?"]})[0] == 200
    return standalone_server


def test_saves_in_a_row_each_with_the_version_it_got_back(srv):
    first = _read(srv, "CASE-A")
    status, out = _save(srv, "CASE-A", first["content"] + "- one\n", first["version"])
    assert status == 200, out
    status, out = _save(srv, "CASE-A", first["content"] + "- one\n- two\n", out["version"])
    assert status == 200, out
    assert _read(srv, "CASE-A")["version"] == out["version"]


@pytest.mark.parametrize("meanwhile", ["other_user", "quick_add", "rerun_fact"])
def test_a_stale_tab_gets_the_current_text_and_overwrites_nothing(srv, meanwhile):
    tab = _read(srv, "CASE-A")
    case_dir = srv["cases_root"] / "CASE-A"
    if meanwhile == "other_user":
        other = _read(srv, "CASE-A")
        assert _save(srv, "CASE-A", other["content"] + "- Who used jane.doe?\n", other["version"])[0] == 200
        marker = "- Who used jane.doe?"
    elif meanwhile == "quick_add":     # the start dialog's questions (run_manager.start)
        case_admin.append_to_brief(str(srv["cases_root"]), "CASE-A", requests=["Was data taken?"])
        marker = "- Was data taken?"
    else:                              # atlas rerun -q (plane_a_scan's analyst feedback)
        case_knowledge.append_facts(case_dir, ["203.0.113.7 is the partner VPN."])
        marker = "203.0.113.7 is the partner VPN."
    status, data = _save(srv, "CASE-A", tab["content"] + "- from the stale tab\n", tab["version"])
    assert status == 409 and data["conflict"] is True
    on_disk = (case_dir / "CASE.md").read_text(encoding="utf-8")
    assert marker in on_disk and "from the stale tab" not in on_disk
    assert data["content"] == on_disk and data["version"] == _read(srv, "CASE-A")["version"]
    # The tab, now on the current version, saves knowingly.
    assert _save(srv, "CASE-A", data["content"] + "- from the stale tab\n", data["version"])[0] == 200


def test_a_save_without_a_version_is_refused(srv):
    before = _read(srv, "CASE-A")["content"]
    status, data = _call(srv, "POST", "case/case_md/save", {"case": "CASE-A", "content": "# gone\n"})
    assert status == 400 and "version" in data["error"]
    assert _read(srv, "CASE-A")["content"] == before


def test_autofill_preview_refuses_a_proposal_made_from_an_older_brief(srv):
    tab = _read(srv, "CASE-A")
    case_admin.append_to_brief(str(srv["cases_root"]), "CASE-A", facts=["CORP-DC01 is the domain controller."])
    status, data = _call(srv, "POST", "case/case_md/autofill_preview",
                         {"case": "CASE-A", "rows": [], "version": tab["version"]})
    assert status == 409 and "Autofill" in data["error"]
    now = _read(srv, "CASE-A")
    status, data = _call(srv, "POST", "case/case_md/autofill_preview",
                         {"case": "CASE-A", "rows": [], "version": now["version"]})
    assert status == 200 and data["version"] == now["version"]


@pytest.fixture
def copied(standalone_server):
    """A case whose folder is not its id, as after a copy: the brief and the
    task store say CASE-A, the folder is case-a-copy."""
    root = standalone_server["cases_root"]
    d = root / "case-a-copy"
    (d / ".atlas").mkdir(parents=True)
    (d / "CASE.md").write_text("**Case ID:** CASE-A\n\n## Investigation Requests\n- What ran on CORP-WS01?\n",
                               encoding="utf-8")
    from core.investigation_tasks import reconcile_case_md
    reconcile_case_md(d, case_id="CASE-A")
    return standalone_server, d


def test_a_brief_save_keeps_the_case_id_the_brief_names(copied):
    srv, d = copied
    tab = _read(srv, "case-a-copy")
    assert _save(srv, "case-a-copy", tab["content"] + "- Was data taken?\n", tab["version"])[0] == 200
    assert load_tasks(d)["case_id"] == "CASE-A"
    case_admin.append_to_brief(str(srv["cases_root"]), "case-a-copy", requests=["Who logged on?"])
    assert load_tasks(d)["case_id"] == "CASE-A"
    tab = _read(srv, "case-a-copy")
    assert _save(srv, "case-a-copy", tab["content"].replace("CASE-A", "CASE-B"), tab["version"])[0] == 200
    assert load_tasks(d)["case_id"] == "CASE-B"     # as a run would write it


def test_a_rename_carries_the_case_id_into_the_task_store(standalone_server):
    root = str(standalone_server["cases_root"])
    case_admin.create_case(root, "CASE-OLD", requests=["What ran on CORP-WS01?"])
    case_admin.move_case(root, "CASE-OLD", "CASE-NEW")
    d = standalone_server["cases_root"] / "CASE-NEW"
    assert "**Case ID:** CASE-NEW" in (d / "CASE.md").read_text(encoding="utf-8")
    assert load_tasks(d)["case_id"] == "CASE-NEW"


def test_create_stores_the_case_id_it_was_given(standalone_server):
    d = case_admin.create_case(str(standalone_server["cases_root"]), "CASE-N", requests=["Why?"])
    assert load_tasks(d)["case_id"] == "CASE-N"
