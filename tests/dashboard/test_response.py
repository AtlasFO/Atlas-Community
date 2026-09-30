"""The Response view: the Overview's summary, the tab's catalog, who may mark
an item done, and the language a case is created with."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from core import claim_graph as cg
from dashboard import auth, read_models

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "CASE-1"
    (d / ".atlas").mkdir(parents=True)
    return d


def _seed(case):
    c = cg.add_claim(case, statement="encryption ran on FILE01", confidence="CONFIRMED",
                     host="FILE01")["node_id"]
    now = cg.add_recommendation(case, action="Isolate FILE01", phase="contain",
                                urgency="now", basis_ids=[c])["node_id"]
    later = cg.add_recommendation(case, action="Review RDP exposure", phase="harden",
                                  urgency="later", basis_ids=[c])["node_id"]
    prior = cg.add_recommendation(case, action="Do not pay the ransom", phase="escalate",
                                  urgency="now", source="prior_knowledge")["node_id"]
    return now, later, prior


class TestSummary:
    def test_counts_and_top_for_the_overview(self, case):
        now, later, prior = _seed(case)
        s = read_models.recommendation_summary(str(case))
        assert (s["total"], s["open"], s["open_now"], s["evidence_backed"]) == (3, 3, 2, 2)
        assert [r["id"] for r in s["top"]] == [now, prior, later]
        assert not s["prior_only"]
        assert "response" in read_models.case_overview(str(case))

    def test_prior_only_is_said_on_the_front_door(self, case):
        cg.add_recommendation(case, action="Preserve volatile state", phase="contain",
                              urgency="now", source="prior_knowledge")
        assert read_models.recommendation_summary(str(case))["prior_only"]

    def test_a_case_without_a_graph_is_empty_not_broken(self, tmp_path):
        s = read_models.recommendation_summary(str(tmp_path / "nothing"))
        assert s["total"] == 0 and s["top"] == []

    def test_the_summary_follows_the_graph(self, case):
        now, _, _ = _seed(case)
        assert read_models.recommendation_summary(str(case))["open_now"] == 2
        cg.set_recommendation_state(case, now, "done")
        assert read_models.recommendation_summary(str(case))["open_now"] == 1


class TestCatalog:
    def test_the_tab_gets_now_and_phase_groups(self, case):
        now, later, prior = _seed(case)
        cat = read_models.recommendation_catalog(str(case))
        assert {r["id"] for r in cat["now"]} == {now, prior}
        assert [g["phase"] for g in cat["groups"]] == ["contain", "harden", "escalate"]
        row = next(r for r in cat["recommendations"] if r["id"] == now)
        assert row["basis"][0]["confidence"] == "CONFIRMED"
        assert row["basis"][0]["statement"].startswith("encryption ran")

    @pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
    def test_the_page_shows_every_open_row_and_done_rows_on_request(self, case, tmp_path):
        """The catalog carries each row twice (ordered list and phase group);
        the page pairs the copies by id, or only the "Do now" block renders."""
        now, later, prior = _seed(case)
        cg.add_recommendation(case, action="Rotate shared credentials", phase="eradicate",
                              urgency="soon", source="prior_knowledge")
        cg.set_recommendation_state(case, later, "done")
        payload = tmp_path / "catalog.json"
        payload.write_text(json.dumps(read_models.recommendation_catalog(str(case))))
        proc = subprocess.run(
            ["node", str(ROOT / "tests/dashboard/response_harness.js"),
             str(ROOT / "dashboard/recommendations.html"), str(payload)],
            capture_output=True, text=True, timeout=30)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "response harness: ok" in proc.stdout


class TestRoles:
    def test_reading_is_for_everyone_and_marking_done_is_not(self):
        assert auth.effective_min_role("case/recommendations") == "viewer"
        assert auth.effective_min_role("case/recommendations/state") == "analyst"

    def test_a_viewer_cannot_change_state(self):
        viewer = auth.User(id=1, username="v", email="", role="viewer",
                           is_active=True, created_at="")
        analyst = auth.User(id=2, username="a", email="", role="analyst",
                            is_active=True, created_at="")
        assert not auth.can_access(viewer, "case/recommendations/state")
        assert auth.can_access(viewer, "case/recommendations")
        assert auth.can_access(analyst, "case/recommendations/state")


class TestCaseLanguage:
    def test_the_language_is_persisted_with_the_case(self, tmp_path):
        from core.case_config import get_report_language
        from dashboard import case_admin
        dest = case_admin.create_case(str(tmp_path), "LANG-1", language="de")
        assert get_report_language(dest) == "de"

    def test_an_empty_language_keeps_the_default(self, tmp_path):
        from core.case_config import DEFAULT_LANGUAGE, get_report_language
        from dashboard import case_admin
        dest = case_admin.create_case(str(tmp_path), "LANG-2")
        assert get_report_language(dest) == DEFAULT_LANGUAGE

    def test_a_bad_language_refuses_before_anything_is_written(self, tmp_path):
        from dashboard import case_admin
        with pytest.raises(case_admin.CaseAdminError, match="unsupported language"):
            case_admin.create_case(str(tmp_path), "LANG-3", language="klingon")
        assert not (tmp_path / "LANG-3").exists()

    def test_the_new_case_form_recommends_english(self):
        page = Path("dashboard/new_case.html").read_text(encoding="utf-8")
        assert 'id="nc-language"' in page
        assert 'value="en" selected' in page
        assert "English is recommended" in page
