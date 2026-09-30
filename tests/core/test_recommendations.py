"""A recommendation is a belief-backed node: it names what it rests on, an
estate-wide one needs evidence beyond one host, restatements fold, and the
report's section is a projection of them."""
import json

import pytest

from core import claim_graph as cg
from core.recommendations import build_catalog, do_now, grouped, render_markdown


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "case"
    (d / ".atlas").mkdir(parents=True)
    return d


def _claim(case, statement, host="", confidence="LIKELY", scope="host"):
    r = cg.add_claim(case, statement=statement, confidence=confidence,
                     host=host, scope=scope)
    assert r["success"], r
    return r["node_id"]


class TestRecording:
    def test_a_recommendation_names_its_basis(self, case):
        c = _claim(case, "toolx.exe was executed from the tempadmin profile",
                   host="FILESRV01", confidence="CONFIRMED")
        r = cg.add_recommendation(case, action="Isolate FILESRV01 from the network",
                                  phase="contain", scope="host", urgency="now",
                                  basis_ids=[c], rationale="lateral movement tool present")
        assert r["success"] and r["node_id"].startswith("R")
        node = cg.get_node(cg.load_graph(case), r["node_id"])
        assert node["kind"] == "recommendation"
        assert node["basis_ids"] == [c]
        assert node["confidence"] == "CONFIRMED"     # never stronger than its basis
        assert node["response_state"] == "open"
        assert node["host"] == "FILESRV01"
        edges = [e for e in cg.load_graph(case)["edges"] if e["to"] == r["node_id"]]
        assert edges and edges[0]["from"] == c and edges[0]["type"] == "derived_from"

    def test_a_basis_is_required_unless_it_is_prior_knowledge(self, case):
        r = cg.add_recommendation(case, action="Do something", phase="contain")
        assert not r["success"] and "basis_ids required" in r["error"]
        r = cg.add_recommendation(case, action="Do not power off affected hosts",
                                  phase="contain", urgency="now",
                                  source="prior_knowledge")
        assert r["success"]
        node = cg.get_node(cg.load_graph(case), r["node_id"])
        assert node["source"] == "prior_knowledge" and node["basis_ids"] == []

    def test_a_basis_must_be_a_current_belief(self, case):
        r = cg.add_recommendation(case, action="x", phase="contain", basis_ids=["C-9999"])
        assert not r["success"] and "not a claim or conclusion" in r["error"]

    def test_estate_scope_needs_evidence_beyond_one_host(self, case):
        c1 = _claim(case, "tempadmin account created", host="FILESRV01")
        r = cg.add_recommendation(case, action="Reset every domain credential",
                                  phase="eradicate", scope="estate", basis_ids=[c1])
        assert not r["success"] and "beyond one host" in r["error"]
        c2 = _claim(case, "the same account logged on to DC01", host="DC01")
        r = cg.add_recommendation(case, action="Reset every domain credential",
                                  phase="eradicate", scope="estate", basis_ids=[c1, c2])
        assert r["success"]
        assert cg.get_node(cg.load_graph(case), r["node_id"])["scope"] == "estate"

    def test_an_estate_scoped_belief_also_reaches(self, case):
        c = _claim(case, "ransomware encrypted shares on several servers",
                   scope="estate", confidence="CONFIRMED")
        r = cg.add_recommendation(case, action="Verify backups before any restore",
                                  phase="recover", scope="estate", basis_ids=[c])
        assert r["success"]

    def test_a_restatement_folds_into_the_existing_one(self, case):
        c = _claim(case, "x", host="FILESRV01")
        first = cg.add_recommendation(case, action="Isolate FILESRV01 from the network",
                                      phase="contain", basis_ids=[c])
        again = cg.add_recommendation(case, action="Network-isolate the host FILESRV01",
                                      phase="contain", basis_ids=[c])
        assert again["duplicate"] and again["node_id"] == first["node_id"]
        other = cg.add_recommendation(case, action="Re-image FILESRV01",
                                      phase="eradicate", basis_ids=[c])
        assert not other.get("duplicate")

    @pytest.mark.parametrize("field,value", [("phase", "panic"), ("scope", "galaxy"),
                                             ("urgency", "eventually"), ("source", "rumour")])
    def test_vocabularies_are_closed(self, case, field, value):
        kw = dict(action="x", phase="contain", source="prior_knowledge")
        kw[field] = value
        r = cg.add_recommendation(case, **kw)
        assert not r["success"] and f"invalid {field}" in r["error"]


class TestState:
    def test_done_and_dismissed_are_bookkeeping_not_belief_status(self, case):
        r = cg.add_recommendation(case, action="x", phase="contain",
                                  source="prior_knowledge")
        out = cg.set_recommendation_state(case, r["node_id"], "done", actor="alice")
        assert out["success"]
        node = cg.get_node(cg.load_graph(case), r["node_id"])
        assert node["response_state"] == "done"
        assert node["state_changed_by"] == "alice" and node["state_changed_at"]
        assert node["status"] == "new"      # the graph's own status is untouched
        assert not cg.set_recommendation_state(case, r["node_id"], "later")["success"]
        assert not cg.set_recommendation_state(case, "C-0001", "done")["success"]

    def test_a_dismissed_one_no_longer_blocks_a_restatement(self, case):
        r = cg.add_recommendation(case, action="Rotate the service password",
                                  phase="eradicate", source="prior_knowledge")
        cg.set_recommendation_state(case, r["node_id"], "dismissed")
        again = cg.add_recommendation(case, action="Rotate the service password",
                                      phase="eradicate", source="prior_knowledge")
        assert again["success"] and not again.get("duplicate")


class TestCatalog:
    def _plan(self, case):
        c_conf = _claim(case, "encryption ran on FILESRV01", host="FILESRV01", confidence="CONFIRMED")
        c_susp = _claim(case, "beaconing seen from WS07", host="WS07", confidence="SUSPECTED")
        ids = {}
        ids["later_conf"] = cg.add_recommendation(
            case, action="Review RDP exposure", phase="harden", urgency="later",
            basis_ids=[c_conf])["node_id"]
        ids["now_susp"] = cg.add_recommendation(
            case, action="Isolate WS07", phase="contain", urgency="now",
            basis_ids=[c_susp])["node_id"]
        ids["now_conf"] = cg.add_recommendation(
            case, action="Isolate FILESRV01", phase="contain", urgency="now",
            basis_ids=[c_conf])["node_id"]
        ids["prior"] = cg.add_recommendation(
            case, action="Do not pay the ransom", phase="escalate", urgency="now",
            source="prior_knowledge")["node_id"]
        return ids

    def test_ordering_open_urgency_basis_scope(self, case):
        ids = self._plan(case)
        cg.set_recommendation_state(case, ids["now_susp"], "done")
        order = [r["id"] for r in build_catalog(case)["recommendations"]]
        # open first; among open+now, the confirmed basis before prior knowledge;
        # later after now; done last
        assert order == [ids["now_conf"], ids["prior"], ids["later_conf"], ids["now_susp"]]

    def test_counts_and_do_now(self, case):
        ids = self._plan(case)
        cat = build_catalog(case)
        assert cat["total"] == 4 and cat["open"] == 4 and cat["open_now"] == 3
        assert cat["by_source"] == {"recorded": 3, "prior_knowledge": 1}
        assert cat["evidence_backed"] == 3
        assert {r["id"] for r in do_now(cat)} == {ids["now_conf"], ids["now_susp"], ids["prior"]}
        phases = [p for p, _ in grouped(cat)]
        assert phases == ["contain", "harden", "escalate"]   # lifecycle order, empties dropped

    def test_a_prior_knowledge_item_is_labelled_not_disguised(self, case):
        self._plan(case)
        rows = {r["id"]: r for r in build_catalog(case)["recommendations"]}
        prior = next(r for r in rows.values() if r["source"] == "prior_knowledge")
        assert prior["basis_confidence"] == "PRIOR" and prior["basis"] == []

    def test_a_recommendation_is_never_superseded_only_closed(self, case):
        """A recommendation leaves the plan through its state, never through
        supersession: the row is the responder's bookkeeping."""
        ids = self._plan(case)
        basis = cg.get_node(cg.load_graph(case), ids["later_conf"])["basis_ids"]
        sharper = cg.add_recommendation(
            case, action="Disable RDP on FILESRV01 until the exposure is reviewed",
            phase="harden", urgency="soon", basis_ids=basis)["node_id"]
        r = cg.supersede(case, ids["later_conf"], sharper, reason="sharper")
        assert not r["success"] and r["gate"] == "recommendation_state"
        assert cg.set_recommendation_state(case, ids["later_conf"], "dismissed")["success"]
        remaining = [r["id"] for r in build_catalog(case)["recommendations"] if r["state"] == "open"]
        assert ids["later_conf"] not in remaining and sharper in remaining

    def test_an_empty_case_is_an_empty_plan(self, tmp_path):
        cat = build_catalog(tmp_path / "nowhere")
        assert cat["total"] == 0 and cat["recommendations"] == []


class TestReportSection:
    def test_the_section_projects_the_plan_with_its_basis(self, case):
        c = _claim(case, "encryption ran on FILESRV01", host="FILESRV01", confidence="CONFIRMED")
        cg.add_recommendation(case, action="Isolate FILESRV01", phase="contain",
                              urgency="now", basis_ids=[c], rationale="stop the spread")
        cg.add_recommendation(case, action="Do not pay the ransom", phase="escalate",
                              source="prior_knowledge")
        text = "\n".join(render_markdown(build_catalog(case), "en"))
        assert "### Do now" in text and "**Isolate FILESRV01**" in text
        assert "recorded by the investigation" in text and "[CONFIRMED]" in text
        assert "stop the spread" in text
        assert "from prior knowledge" in text and "prior knowledge" in text.lower()

    def test_german_labels(self, case):
        cg.add_recommendation(case, action="Backups prüfen", phase="recover",
                              source="prior_knowledge")
        text = "\n".join(render_markdown(build_catalog(case), "de"))
        assert "### Wiederherstellen" in text and "aus Vorwissen" in text

    def test_a_host_report_shows_its_host_and_points_at_the_estate(self, case):
        c1 = _claim(case, "x", host="FILESRV01")
        c2 = _claim(case, "y", host="DC01")
        cg.add_recommendation(case, action="Isolate FILESRV01", phase="contain",
                              basis_ids=[c1], hosts=["FILESRV01"])
        cg.add_recommendation(case, action="Isolate DC01", phase="contain",
                              basis_ids=[c2], hosts=["DC01"])
        cg.add_recommendation(case, action="Reset every domain credential",
                              phase="eradicate", scope="estate", basis_ids=[c1, c2])
        text = "\n".join(render_markdown(build_catalog(case), "en",
                                         host="FILESRV01", report_scope="host"))
        assert "Isolate FILESRV01" in text and "Isolate DC01" not in text
        assert "Reset every domain credential" not in text
        assert "estate report" in text

    def test_dismissed_items_are_left_out_of_the_report(self, case):
        r = cg.add_recommendation(case, action="Rotate keys", phase="eradicate",
                                  source="prior_knowledge")
        cg.set_recommendation_state(case, r["node_id"], "dismissed")
        text = "\n".join(render_markdown(build_catalog(case), "en"))
        assert "Rotate keys" not in text


class TestDerivedFromFindingText:
    """Precautions derive from what a finding asserts, not from a word in it."""

    def test_a_tool_that_names_passwords_earns_no_precaution(self, case):
        from core.recommendations import derive_from_finding_text
        stmt = "Hacking toolset on the desktop: 12 shortcuts, among them Cain v2.5 (password recovery)"
        cid = _claim(case, stmt)
        out = derive_from_finding_text(case, cid, stmt)
        assert out["classes"] == [] and out["recorded"] == []
        assert build_catalog(case)["recommendations"] == []

    def test_dumped_credentials_earn_the_credential_precautions(self, case):
        from core.recommendations import derive_from_finding_text
        stmt = "NTDS.dit was dumped and the domain credentials harvested with secretsdump"
        cid = _claim(case, stmt)
        out = derive_from_finding_text(case, cid, stmt)
        assert "credential_compromise" in out["classes"] and out["recorded"]
        actions = {r["action"] for r in build_catalog(case)["recommendations"]}
        assert any("Reset the affected credentials" in a for a in actions)


class TestExamination:
    """Whose system the evidence comes from decides what a recommendation
    may be: on a victim's system examined after the fact the finding-derived
    precautions are recorded as on a live incident and a mitigation is a
    lesson (harden, later); on the device of the person under investigation
    nothing is recorded; the section says why in both languages, and the
    readiness advisory asks for no plan on a suspect's device."""

    MITIGATIONS = str(__import__("pathlib").Path(__file__).resolve().parents[2]
                      / "share" / ".common" / "mitre_mitigations.json")

    def _case(self, tmp_path, engagement="examination", owner="suspect"):
        d = tmp_path / "case"
        (d / ".atlas").mkdir(parents=True)
        lines = ["**Case ID:** X"]
        if engagement:
            lines.append(f"**Engagement:** {engagement}")
        if owner:
            lines.append(f"**System owner:** {owner}")
        (d / "CASE.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return d

    def test_a_suspects_device_gets_no_finding_precaution(self, tmp_path):
        from core.recommendations import derive_from_finding_text
        d = self._case(tmp_path)
        c = _claim(d, "Files on the share were encrypted by the ransomware and a ransom note dropped",
                   host="FILESRV01", confidence="CONFIRMED")
        r = derive_from_finding_text(d, c, "Files on the share were encrypted by the ransomware",
                                     host="FILESRV01")
        assert r["recorded"] == [] and "suspect" in r["skipped"]
        assert build_catalog(d)["total"] == 0

    def test_a_victims_finding_precautions_survive_the_examination(self, tmp_path):
        """Examined after the fact, the owner's live estate still needs the
        steps the finding warrants; only the note and the order change."""
        from core.recommendations import derive_from_finding_text
        d = self._case(tmp_path, owner="victim")
        c = _claim(d, "Files on the share were encrypted by the ransomware and a ransom note dropped",
                   host="FILESRV01", confidence="CONFIRMED")
        r = derive_from_finding_text(d, c, "Files on the share were encrypted by the ransomware",
                                     host="FILESRV01")
        assert r["recorded"] and not r.get("skipped")
        e = self._case(tmp_path / "live", engagement="incident-response", owner="victim")
        c2 = _claim(e, "Files on the share were encrypted by the ransomware and a ransom note dropped",
                    host="FILESRV01", confidence="CONFIRMED")
        derive_from_finding_text(e, c2, "Files on the share were encrypted by the ransomware",
                                 host="FILESRV01")
        after = [(x["action"], x["phase"], x["urgency"]) for x in build_catalog(d)["recommendations"]]
        live = [(x["action"], x["phase"], x["urgency"]) for x in build_catalog(e)["recommendations"]]
        assert sorted(after) == sorted(live)

    def test_a_mitigation_is_a_lesson_for_a_victim_and_nothing_for_a_suspect(self, tmp_path):
        from core.recommendations import derive_from_claim
        d = self._case(tmp_path, owner="victim")
        c = _claim(d, "RDP brute force (T1110.001) against DC01 from 194.61.24.102 succeeded",
                   host="DC01", confidence="CONFIRMED")
        # a mitigation with nothing to act on is a reference, not a row
        assert derive_from_claim(d, c, mitigations_path=self.MITIGATIONS)["recorded"] == []
        _rows(d, c, [{"type": "account", "value": "admin", "side": "victim"}])
        r = derive_from_claim(d, c, mitigations_path=self.MITIGATIONS)
        assert r["recorded"], r
        rows = build_catalog(d)["recommendations"]
        assert rows and all(x["phase"] == "harden" and x["urgency"] == "later" for x in rows)
        assert do_now(build_catalog(d)) == []
        e = self._case(tmp_path / "suspect")
        c2 = _claim(e, "RDP brute force (T1110.001) against DC01 from 194.61.24.102 succeeded",
                    host="DC01", confidence="CONFIRMED")
        r2 = derive_from_claim(e, c2, mitigations_path=self.MITIGATIONS)
        assert r2["recorded"] == [] and "suspect" in r2["skipped"] and r2["techniques"]
        assert build_catalog(e)["total"] == 0

    def test_the_section_says_why_in_both_languages(self, tmp_path):
        d = self._case(tmp_path, owner="victim")
        cat = build_catalog(d)
        assert cat["engagement"] == "examination" and cat["system_owner"] == "victim"
        en = render_markdown(cat, "en")
        de = render_markdown(cat, "de")
        assert "examination after the fact" in en[0] and "still in service" in en[0]
        assert "nachträgliche Untersuchung" in de[0]
        assert not any("first-hour" in x and "no " in x for x in en)
        c = _claim(d, "RDP brute force (T1110.001) against DC01 succeeded", host="DC01")
        cg.add_recommendation(d, action="Retire the exposed RDP listener", phase="harden",
                              urgency="later", basis_ids=[c])
        lines = render_markdown(build_catalog(d), "en")
        assert "examination after the fact" in lines[0]
        assert any("Retire the exposed RDP listener" in x for x in lines)
        s = self._case(tmp_path / "suspect")
        en_s = render_markdown(build_catalog(s), "en")
        de_s = render_markdown(build_catalog(s), "de")
        assert "person under investigation" in en_s[0] and "examination" not in en_s[0]
        assert "beschuldigten Person" in de_s[0]

    def test_an_incident_on_a_victims_system_carries_no_note(self, tmp_path):
        d = self._case(tmp_path, engagement="incident-response", owner="victim")
        cat = build_catalog(d)
        assert cat["engagement"] == "incident-response" and cat["system_owner"] == "victim"
        lines = render_markdown(cat, "en")
        assert not any("examination" in x or "assume" in x for x in lines)

    def test_a_brief_without_either_row_states_the_assumption_once(self, tmp_path):
        d = tmp_path / "case"
        (d / ".atlas").mkdir(parents=True)
        cat = build_catalog(d)
        assert cat["engagement"] == "incident-response" and cat["system_owner"] == "unknown"
        en = render_markdown(cat, "en")
        de = render_markdown(cat, "de")
        assert sum("assume the owner is the victim" in x for x in en) == 1
        assert sum("Eigentümer das Opfer ist" in x for x in de) == 1
        assert not any("examination" in x for x in en)
        # Everything but that one line is what the section rendered before
        # the field existed.
        stated = self._case(tmp_path / "stated", engagement="incident-response", owner="victim")
        without = [x for x in en if "assume the owner is the victim" not in x]
        assert [x for x in without if x] == [x for x in render_markdown(build_catalog(stated), "en") if x]

    def test_the_readiness_advisory_asks_for_no_plan_on_a_suspects_device(self, tmp_path):
        from core.recommendations import report_readiness_advisories
        d = self._case(tmp_path)
        _claim(d, "The laptop was used by one local account", host="WS01", confidence="CONFIRMED")
        assert report_readiness_advisories(d, ["WS01"], 1) == []
        v = self._case(tmp_path / "victim", owner="victim")
        _claim(v, "The laptop was used by one local account", host="WS01", confidence="CONFIRMED")
        assert report_readiness_advisories(v, ["WS01"], 1)
        e = tmp_path / "incident"
        (e / ".atlas").mkdir(parents=True)
        _claim(e, "The laptop was used by one local account", host="WS01", confidence="CONFIRMED")
        assert report_readiness_advisories(e, ["WS01"], 1)

    def test_the_dashboard_catalog_carries_the_engagement_and_the_owner(self, tmp_path):
        from dashboard.read_models import recommendation_catalog
        d = self._case(tmp_path)
        cat = recommendation_catalog(d)
        assert cat["engagement"] == "examination" and cat["system_owner"] == "suspect"




# ── objects, phases and the rows the batch derives ───────────────────────

def _rows(case, cid, rows):
    r = cg.set_claim_indicators(case, cid, rows)
    assert r["success"], r


def _brief(case, text):
    (case / "CASE.md").write_text(text, encoding="utf-8")


class TestObjects:
    def test_objects_come_from_typed_rows_and_an_objectless_step_waits_to_be_scoped(self, case):
        from core.recommendations import derive_from_finding_text
        c = _claim(case, "Data was exfiltrated to 198.51.100.7 and relay.example.net from FS01.", host="FS01", confidence="CONFIRMED")
        _rows(case, c, [{"type": "ip", "value": "198.51.100.7", "side": "attacker"},
                        {"type": "domain", "value": "relay.example.net", "side": "attacker"}])
        r = derive_from_finding_text(case, c, "Data was exfiltrated to 198.51.100.7 and relay.example.net from FS01.", host="FS01")
        rows = {x["id"]: x for x in build_catalog(case)["recommendations"]}
        block = [x for x in rows.values() if x["action"].startswith("Block the identified egress destinations")]
        assert block and block[0]["urgency"] == "now"
        assert block[0]["action"].endswith(": 198.51.100.7, relay.example.net")
        assert block[0]["objects"] == ["198.51.100.7", "relay.example.net"]
        preserve = [x for x in rows.values() if x["action"].startswith("Preserve proxy, firewall and DNS logs")]
        assert preserve and preserve[0]["action"].endswith(": FS01")
        # a malware finding without rows: the block step waits to be scoped, never "now"
        m = _claim(case, "A trojan was found on WS02.", host="WS02", confidence="LIKELY")
        derive_from_finding_text(case, m, "A trojan was found on WS02.", host="WS02")
        rows = {x["id"]: x for x in build_catalog(case)["recommendations"]}
        c2 = [x for x in rows.values() if x["action"].startswith("Block the known command-and-control")]
        assert c2 and c2[0]["urgency"] == "soon" and "to be scoped" in c2[0]["rationale"] and c2[0]["objects"] == []
        isolate = [x for x in rows.values() if x["action"].startswith("Isolate the affected host")]
        assert isolate and isolate[0]["action"].endswith(": WS02") and isolate[0]["urgency"] == "now"

    def test_an_open_row_is_extended_in_place_and_a_done_row_gets_a_new_row(self, case):
        from core.recommendations import derive_from_finding_text
        text = "A trojan was found on WS02 and beaconed out."
        m = _claim(case, text, host="WS02", confidence="LIKELY")
        derive_from_finding_text(case, m, text, host="WS02")
        first = {x["id"]: x for x in build_catalog(case)["recommendations"]}
        rid = next(i for i, x in first.items() if x["action"].startswith("Block the known command-and-control"))
        assert first[rid]["urgency"] == "soon"
        _rows(case, m, [{"type": "domain", "value": "c2.example.net", "side": "attacker"}])
        r = derive_from_finding_text(case, m, text, host="WS02")
        assert rid in r["folded"]
        after = {x["id"]: x for x in build_catalog(case)["recommendations"]}
        assert after[rid]["objects"] == ["c2.example.net"] and after[rid]["urgency"] == "now"
        assert after[rid]["action"].endswith(": c2.example.net") and "extended with c2.example.net" in after[rid]["rationale"]
        # closed rows keep their record: a new object makes a new row
        cg.set_recommendation_state(case, rid, "done", note="blocked at the perimeter")
        _rows(case, m, [{"type": "ip", "value": "203.0.113.5", "side": "attacker"}])
        r = derive_from_finding_text(case, m, text, host="WS02")
        assert rid not in r["folded"] and len(r["recorded"]) == 1
        new = {x["id"]: x for x in build_catalog(case)["recommendations"]}[r["recorded"][0]]
        assert "203.0.113.5" in new["objects"] and new["state"] == "open"
        assert {x["id"]: x for x in build_catalog(case)["recommendations"]}[rid]["objects"] == ["c2.example.net"]

    def test_decision_rows_keep_their_urgency_without_objects(self, case):
        from core.recommendations import derive_from_finding_text
        text = "Files were encrypted and a ransom note was left on FS01."
        c = _claim(case, text, host="FS01", confidence="CONFIRMED")
        derive_from_finding_text(case, c, text, host="FS01")
        rows = build_catalog(case)["recommendations"]
        decide = [x for x in rows if x["action"].startswith("Do not pay")]
        assert decide and decide[0]["urgency"] == "now" and "to be scoped" not in decide[0]["rationale"]

    def test_block_objects_never_include_an_own_asset(self, case):
        from core.recommendations import derive_from_finding_text
        _brief(case, "# Case: X\n\n**Case ID:** X\n\n## Evidence\n\n| Label | Kind | Path |\n|---|---|---|\n| FS01 | disk | fs01.E01 |\n")
        text = "Data was exfiltrated to 198.51.100.7 from FS01."
        c = _claim(case, text, host="FS01", confidence="CONFIRMED")
        _rows(case, c, [{"type": "ip", "value": "198.51.100.7", "side": "attacker"},
                        {"type": "host", "value": "FS01", "side": "attacker"}])
        derive_from_finding_text(case, c, text, host="FS01")
        block = [x for x in build_catalog(case)["recommendations"] if x["action"].startswith("Block the identified")]
        assert block and "FS01" not in block[0]["objects"] and block[0]["objects"] == ["198.51.100.7"]


class TestMitigations:
    def test_one_row_per_technique_with_objects_and_none_without(self, case):
        from core.recommendations import derive_from_claim, hardening_references
        c = _claim(case, "Valid accounts were used for access (T1078) on DC01.", host="DC01", confidence="CONFIRMED")
        assert derive_from_claim(case, c)["recorded"] == []            # no objects: no row
        _rows(case, c, [{"type": "account", "value": "jane", "side": "victim"},
                        {"type": "account", "value": "svc.backup01", "side": "attacker"}])
        r = derive_from_claim(case, c)
        assert len(r["recorded"]) == 1
        row = {x["id"]: x for x in build_catalog(case)["recommendations"]}[r["recorded"][0]]
        assert row["phase"] == "harden" and row["urgency"] == "later"
        assert row["action"].startswith("Harden the accounts the finding names against T1078: jane, svc.backup01 (M1")
        assert "MITRE ATT&CK mitigation M1" in row["rationale"] and row["objects"] == ["jane", "svc.backup01"]
        refs = hardening_references(case)
        assert refs and "T1078: M1" in refs[0] and refs[0].startswith("*Hardening references")


class TestTypedRowRows:
    def test_preservation_requests_and_victims_in_the_subject_frame(self, case):
        from core.recommendations import derive_from_typed_rows
        _brief(case, "# Case: X\n\n**Case ID:** X\n**Engagement:** examination\n**System owner:** suspect\n")
        c = _claim(case, "The subject mailed the plan to a contact and named a target.", host="LAPTOP", confidence="CONFIRMED")
        _rows(case, c, [{"type": "email", "value": "subj@gmail.com", "side": "subject"},
                        {"type": "email", "value": "contact@custom.example", "side": "third_party"},
                        {"type": "account", "value": "target.person", "side": "victim"}])
        r = derive_from_typed_rows(case, c)
        rows = {x["id"]: x for x in build_catalog(case)["recommendations"]}
        actions = [rows[i]["action"] for i in r["recorded"]]
        assert any(a == "Have law enforcement or counsel request preservation from Google: subj@gmail.com" for a in actions)
        assert any("the mail provider of custom.example (identify it from its MX records): contact@custom.example" in a for a in actions)
        victim = [rows[i] for i in r["recorded"] if rows[i]["phase"] == "escalate"]
        assert victim and victim[0]["action"].endswith("for notification: target.person") and victim[0]["urgency"] == "now"
        assert all(rows[i]["phase"] in ("investigate", "escalate") for i in r["recorded"])
        assert derive_from_typed_rows(case, c)["recorded"] == []       # idempotent

    def test_a_provider_held_subject_value_is_requested_in_the_incident_frame_too(self, case):
        from core.recommendations import derive_from_typed_rows
        _brief(case, "# Case: X\n\n**Case ID:** X\n**System owner:** victim\n**Subject:** J. Doe\n")
        c = _claim(case, "The insider mailed documents out.", host="PC01", confidence="CONFIRMED")
        _rows(case, c, [{"type": "email", "value": "jdoe@example.org", "side": "subject"},
                        {"type": "file", "value": "plans.docx", "side": "victim"}])
        r = derive_from_typed_rows(case, c)
        rows = {x["id"]: x for x in build_catalog(case)["recommendations"]}
        assert len(r["recorded"]) == 1 and rows[r["recorded"][0]]["phase"] == "investigate"
        assert "the mail provider of example.org" in rows[r["recorded"][0]]["action"]


class TestNextSteps:
    def test_open_parts_become_investigate_rows_that_close_when_answered(self, case):
        from core.investigation_tasks import load_tasks, reconcile_case_md, save_tasks
        from core.recommendations import derive_next_steps
        _brief(case, "**Case ID:** X\n\n## Investigation Requests\n"
                     "- Baseline — the operating system and the time zone of the workstation.\n")
        reconcile_case_md(case)
        r = derive_next_steps(case)
        assert len(r["recorded"]) == 1
        row = {x["id"]: x for x in build_catalog(case)["recommendations"]}[r["recorded"][0]]
        assert row["phase"] == "investigate" and row["source"] == "gap" and row["urgency"] == "soon"
        assert row["action"].startswith("Answer the open parts of the request 'Baseline") and row["objects"]
        assert derive_next_steps(case)["recorded"] == []               # folded, not doubled
        store = load_tasks(case)
        for p in store["tasks"][0]["parts"]:
            p["status"] = "answered"
        save_tasks(case, store)
        r2 = derive_next_steps(case)
        assert r2["closed"] == [row["id"]]
        assert {x["id"]: x for x in build_catalog(case)["recommendations"]}[row["id"]]["state"] == "done"


class TestCoverageWarning:
    def test_a_finding_without_a_step_is_listed_and_a_step_quiets_it(self, case):
        from core.recommendations import coverage_warning
        c = _claim(case, "Persistence via a scheduled task (T1053.005) on WS01.", host="WS01", confidence="CONFIRMED")
        w = coverage_warning(case)
        assert c in w and "claim.add_indicators" in w and "add objects" not in w
        cg.add_recommendation(case, action="Remove the scheduled task on WS01", phase="eradicate",
                              scope="host", urgency="now", basis_ids=[c])
        assert coverage_warning(case) == ""


class TestPhases:
    def test_investigate_is_a_phase_ordered_by_frame(self, case):
        from core.recommendations import order_key
        c = _claim(case, "A finding on WS01.", host="WS01", confidence="CONFIRMED")
        ids = {}
        for phase in ("harden", "investigate", "contain", "escalate"):
            r = cg.add_recommendation(case, action=f"Step in {phase} on WS01", phase=phase,
                                      scope="host", urgency="soon", basis_ids=[c])
            assert r["success"], r
            ids[phase] = r["node_id"]
        rows = build_catalog(case)["recommendations"]
        by_phase = lambda frame: [x["phase"] for x in sorted(rows, key=lambda x: order_key(x, frame))]
        assert by_phase("incident") == ["contain", "investigate", "harden", "escalate"]
        assert by_phase("subject") == ["investigate", "escalate", "contain", "harden"]
        text = "\n".join(render_markdown(build_catalog(case), "en"))
        assert "### Next investigative steps" in text
        assert "### Nächste Ermittlungsschritte" in "\n".join(render_markdown(build_catalog(case), "de"))
        assert not cg.add_recommendation(case, action="x", phase="triage", scope="host", urgency="soon", basis_ids=[c])["success"]

    def test_a_gap_row_needs_no_basis_and_objects_are_capped_in_the_text(self, case):
        from core.recommendations import action_text
        r = cg.add_recommendation(case, action="Examine the pagefile", phase="investigate", scope="host",
                                  urgency="soon", source="gap", rationale="unit x is unexamined at report time")
        assert r["success"]
        assert action_text("Block", [f"v{i}" for i in range(10)]) == "Block: v0, v1, v2, v3, v4, v5, v6, v7 and 2 more"
        assert action_text("Block", [f"v{i}" for i in range(9)], "de").endswith("und 1 weitere")



class TestFoldingRules:
    def test_preservation_requests_to_different_providers_stay_apart(self, case):
        from core.recommendations import derive_from_typed_rows
        _brief(case, "# Case: X\n\n**Case ID:** X\n**Engagement:** examination\n**System owner:** suspect\n")
        c = _claim(case, "The subject used two mailboxes.", host="LAPTOP", confidence="CONFIRMED")
        _rows(case, c, [{"type": "email", "value": "jdoe@gmail.com", "side": "subject"},
                        {"type": "email", "value": "jdoe@outlook.com", "side": "subject"},
                        {"type": "email", "value": "a@one.example", "side": "subject"},
                        {"type": "email", "value": "b@two.example", "side": "subject"}])
        r = derive_from_typed_rows(case, c)
        rows = {x["id"]: x for x in build_catalog(case)["recommendations"]}
        actions = sorted(rows[i]["action"] for i in r["recorded"])
        assert len(actions) == 4
        assert any(a.endswith("from Google: jdoe@gmail.com") for a in actions)
        assert any(a.endswith("from Microsoft: jdoe@outlook.com") for a in actions)
        assert any("of one.example" in a and a.endswith(": a@one.example") for a in actions)
        assert any("of two.example" in a and a.endswith(": b@two.example") for a in actions)

    def test_a_basis_after_closure_opens_a_new_row_and_a_mandatory_one_stays_mandatory(self, case):
        from core.recommendations import coverage_warning, derive_from_finding_text
        text = "Credentials were stolen from WS01 (T1003)."
        c1 = _claim(case, text, host="WS01", confidence="CONFIRMED")
        _rows(case, c1, [{"type": "account", "value": "jane", "side": "victim"}])
        derive_from_finding_text(case, c1, text, host="WS01")
        rows = {x["id"]: x for x in build_catalog(case)["recommendations"]}
        reset = next(i for i, x in rows.items() if x["action"].startswith("Reset the affected credentials"))
        cg.set_recommendation_state(case, reset, "done", note="reset on the day")
        # the same indication again: folds, nothing changes
        c2 = _claim(case, "The same theft, restated (T1003).", host="WS01", confidence="CONFIRMED")
        _rows(case, c2, [{"type": "account", "value": "jane", "side": "victim"}])
        r = derive_from_finding_text(case, c2, "Credentials were stolen from WS01 (T1003).", host="WS01")
        assert reset in r["folded"]
        # new evidence after closure: a new open row, and the warning names the new claim until then
        c3 = _claim(case, "Domain-admin hashes were stolen from DC01 (T1003).", host="DC01", confidence="CONFIRMED")
        _rows(case, c3, [{"type": "account", "value": "svc.backup01", "side": "victim"}])
        r = derive_from_finding_text(case, c3, "Credentials were stolen from DC01 (T1003).", host="DC01")
        new = [i for i in r["recorded"] if build_catalog(case)["recommendations"] and
               {x["id"]: x for x in build_catalog(case)["recommendations"]}[i]["action"].startswith("Reset the affected credentials")]
        assert new and new[0] != reset
        assert coverage_warning(case) == ""
        # a done mandatory escalation: a later indication gets its own mandatory row
        v1 = _claim(case, "The notes describe the planned shooting at the school.", host="LAPTOP", confidence="CONFIRMED")
        derive_from_finding_text(case, v1, "The notes describe the planned shooting at the school.", host="LAPTOP")
        rows = {x["id"]: x for x in build_catalog(case)["recommendations"]}
        esc = next(i for i, x in rows.items() if x["mandatory"] and "planned violence" in x["action"])
        cg.set_recommendation_state(case, esc, "done", note="passed to the police")
        v2 = _claim(case, "The chats describe the planned bombing of the station.", host="LAPTOP", confidence="CONFIRMED")
        r = derive_from_finding_text(case, v2, "The chats describe the planned bombing of the station.", host="LAPTOP")
        rows = {x["id"]: x for x in build_catalog(case)["recommendations"]}
        fresh = [rows[i] for i in r["recorded"] if "planned violence" in rows[i]["action"]]
        assert fresh and fresh[0]["mandatory"] and fresh[0]["state"] == "open" and fresh[0]["id"] != esc

    def test_an_extended_row_keeps_every_object_in_its_text(self, case):
        from core.recommendations import derive_from_finding_text
        text = "A trojan on WS02 beaconed out."
        m = _claim(case, text, host="WS02", confidence="LIKELY")
        _rows(case, m, [{"type": "ip", "value": "198.51.100.7", "side": "attacker"}])
        derive_from_finding_text(case, m, text, host="WS02")
        _rows(case, m, [{"type": "ip", "value": "203.0.113.9", "side": "attacker"}])
        derive_from_finding_text(case, m, text, host="WS02")
        row = next(x for x in build_catalog(case)["recommendations"] if x["action"].startswith("Block the known command-and-control"))
        assert row["objects"] == ["198.51.100.7", "203.0.113.9"]
        assert row["action"].endswith(": 198.51.100.7, 203.0.113.9")

    def test_next_step_rows_for_different_units_and_requests_stay_apart(self, case):
        from core.investigation_tasks import reconcile_case_md
        from core.recommendations import derive_next_steps
        _brief(case, "**Case ID:** X\n\n## Investigation Requests\n"
                     "- Timeline — the first and the last event on the workstation.\n"
                     "- Timeline — the first and the last event on the server.\n")
        reconcile_case_md(case)
        r = derive_next_steps(case)
        assert len(r["recorded"]) == 2
        assert cg.add_recommendation(case, action="Examine C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", phase="investigate",
                                     scope="host", urgency="soon", source="gap", fold_exact=True)["node_id"] != \
            cg.add_recommendation(case, action="Examine C:\\Windows\\System32\\winevt\\Logs\\System.evtx", phase="investigate",
                                  scope="host", urgency="soon", source="gap", fold_exact=True)["node_id"]

    def test_the_owners_own_mailbox_gets_a_legal_hold_not_legal_process(self, case):
        from core.recommendations import derive_from_typed_rows
        _brief(case, "# Case: X\n\n**Case ID:** X\n**System owner:** victim\n\n## Hosts\n\n"
                     "| Host | IP | Domain |\n|---|---|---|\n| MAIL01 | 192.0.2.5 | corp.example |\n")
        c = _claim(case, "Mail was forwarded from the executive's mailbox to an outside address.", host="MAIL01", confidence="CONFIRMED")
        # the analyst sided the executive's mailbox as a third party's; its domain is the owner's
        _rows(case, c, [{"type": "email", "value": "ceo@corp.example", "side": "third_party"},
                        {"type": "email", "value": "outside@other.example", "side": "third_party"}])
        r = derive_from_typed_rows(case, c)
        rows = {x["id"]: x for x in build_catalog(case)["recommendations"]}
        actions = [rows[i]["action"] for i in r["recorded"]]
        assert any(a.startswith("Place the owner's own mailboxes and accounts under legal hold: ceo@corp.example") for a in actions)
        assert not any("corp.example (identify" in a for a in actions)
        assert any("of other.example" in a for a in actions)

    def test_the_german_preservation_text_declines_the_article(self, case):
        from core.recommendations import derive_from_typed_rows
        _brief(case, "# Case: X\n\n**Case ID:** X\n**Report language:** de\n**Engagement:** examination\n**System owner:** suspect\n")
        c = _claim(case, "Zwei Postfächer wurden benutzt.", host="LAPTOP", confidence="CONFIRMED")
        _rows(case, c, [{"type": "email", "value": "x@gmail.com", "side": "subject"},
                        {"type": "email", "value": "y@custom.example", "side": "subject"}])
        r = derive_from_typed_rows(case, c, "de")
        rows = {x["id"]: x for x in build_catalog(case)["recommendations"]}
        actions = [rows[i]["action"] for i in r["recorded"]]
        assert any("Beweissicherung bei Google anfordern lassen: x@gmail.com" in a for a in actions)
        assert any("Beweissicherung beim Mailanbieter von custom.example (über die MX-Einträge ermitteln) anfordern lassen: y@custom.example" in a for a in actions)

    def test_the_universal_precaution_names_system_hosts_only(self, tmp_path):
        from core.evidence_links import empty_links, save_evidence_links
        from core.ir_playbook import seed_from_intake
        d = tmp_path / "CASE"
        (d / ".atlas").mkdir(parents=True)
        (d / "CASE.md").write_text("# Case: X\n\n**Case ID:** X\n**System owner:** victim\n\n## Hosts\n\n"
                                   "| Host | IP |\n|---|---|\n| RM#1 | - |\n| RM#3 type1 | - |\n\n"
                                   "## Prior knowledge\n\nWe suspect ransomware; files were encrypted.\n", encoding="utf-8")
        links = empty_links("X")
        links["entries"] += [{"label": "PC", "kind": "disk", "path": "pc.E01", "host": "PC"},
                             {"label": "RM#1", "kind": "disk", "path": "rm1.dd", "host": "RM#1"},
                             {"label": "capture", "kind": "pcap", "path": "c.pcap", "host": ""}]
        save_evidence_links(d, links)
        # no baseline, no memory or live evidence: the claim hosts that match a disk entry stand in
        _claim(d, "A logon on PC.", host="PC")
        _claim(d, "Files on RM#1.", host="RM#1")
        _claim(d, "A note about SRV9.", host="SRV9")
        seed_from_intake(d)
        row = next(x for x in build_catalog(d)["recommendations"] if x["action"].startswith("Preserve volatile state"))
        assert sorted(row["objects"]) == ["PC", "RM#1"]
        # with a baseline installation the systems are the installations alone
        folder = d / "analysis" / "baseline"
        folder.mkdir(parents=True)
        (folder / "pc.json").write_text(json.dumps({"installation": "pc", "identity": {"computer_name": "PC"}}), encoding="utf-8")
        seed_from_intake(d)
        row = {x["id"]: x for x in build_catalog(d)["recommendations"]}[row["id"]]
        assert row["objects"] == ["PC"] and row["action"].endswith(": PC")


class TestExaminationFollowups:
    """On a device examined after the fact the follow-ups the findings open
    come before lessons for the owner, and the pre-report check asks for
    them when findings name a third party's records and none rests on any
    finding."""

    def _case(self, tmp_path, engagement="examination"):
        d = tmp_path / "case"
        (d / ".atlas").mkdir(parents=True)
        lines = ["**Case ID:** X", "**System owner:** victim"]
        if engagement:
            lines.append(f"**Engagement:** {engagement}")
        (d / "CASE.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return d

    def _plan(self, d):
        strong = _claim(d, "A tool was installed on WS01.", host="WS01", confidence="CONFIRMED")
        weak = _claim(d, "The account owner logged on from the tool.", host="WS01", confidence="LIKELY")
        for phase, basis in (("harden", strong), ("contain", strong), ("investigate", weak), ("escalate", weak)):
            r = cg.add_recommendation(d, action=f"Step in {phase} on WS01", phase=phase,
                                      scope="host", urgency="soon", basis_ids=[basis])
            assert r["success"], r
        cat = build_catalog(d)
        return [r["phase"] for r in cat["recommendations"]], [p for p, _ in grouped(cat)]

    def test_follow_ups_come_first_on_an_examination_only(self, tmp_path):
        flat, groups = self._plan(self._case(tmp_path / "exam"))
        assert flat == ["investigate", "escalate", "harden", "contain"]
        assert groups == ["investigate", "escalate", "harden", "contain"]
        flat, groups = self._plan(self._case(tmp_path / "ir", engagement=""))
        assert flat == ["contain", "harden", "investigate", "escalate"]
        assert groups == ["contain", "investigate", "harden", "escalate"]

    def test_the_report_section_follows_the_examination_order(self, tmp_path):
        d = self._case(tmp_path)
        self._plan(d)
        text = "\n".join(render_markdown(build_catalog(d), "en"))
        assert text.index("### Next investigative steps") < text.index("### Escalate") < text.index("### Contain")

    def test_the_warning_asks_for_follow_ups_until_one_rests_on_a_finding(self, tmp_path):
        from core.recommendations import followup_warning
        d = self._case(tmp_path)
        quiet = _claim(d, "A scheduled task ran from 192.168.1.20 on WS01.", host="WS01", confidence="CONFIRMED")
        assert followup_warning(d) == ""
        named = _claim(d, "The user sent the file to drop@example.org from WS01.", host="WS01", confidence="LIKELY")
        typed = _claim(d, "The local account ran the tool on WS01.", host="WS01", confidence="CONFIRMED")
        _rows(d, typed, [{"type": "account", "value": "tempadmin", "side": "victim"}])
        w = followup_warning(d)
        assert typed in w and named in w and quiet not in w and "claim.record_recommendation" in w
        assert w.index(typed) < w.index(named)          # CONFIRMED first
        cg.add_recommendation(d, action="Harden WS01", phase="harden", scope="host", urgency="later", basis_ids=[typed])
        assert followup_warning(d)                       # a lesson is no answer
        cg.add_recommendation(d, action="Identify the holder of drop@example.org", phase="investigate",
                              scope="host", urgency="soon", basis_ids=[named])
        assert followup_warning(d) == ""

    def test_the_warning_is_silent_outside_an_examination(self, tmp_path):
        from core.recommendations import followup_warning
        d = self._case(tmp_path, engagement="")
        _claim(d, "The user sent the file to drop@example.org from WS01.", host="WS01", confidence="CONFIRMED")
        assert followup_warning(d) == ""


class TestBasisOutlived:
    """A step rests on current beliefs: a revision carries it to the
    successor, a withdrawal leaves it held back for review, never in Do
    now, with the withdrawal reason in the report."""

    def test_supersede_carries_the_basis(self, case):
        old = _claim(case, "Service PSEXESVC installed on WS01.", host="WS01", confidence="CONFIRMED")
        new = _claim(case, "Service PSEXESVC installed on WS01 at 12:00 UTC by admin.", host="WS01", confidence="CONFIRMED")
        rid = cg.add_recommendation(case, action="Remove the service on WS01", phase="eradicate", scope="host",
                                    urgency="now", basis_ids=[old])["node_id"]
        assert cg.supersede(case, old, new, reason="sharper statement")["success"]
        row = next(r for r in build_catalog(case)["recommendations"] if r["id"] == rid)
        assert [b["id"] for b in row["basis"]] == [new] and row["basis_confidence"] == "CONFIRMED"
        assert not row["basis_lost"]
        assert load_graph_rec(case, rid)["basis_carried_from"] == [old]

    def test_a_withdrawn_basis_holds_the_step_back(self, case):
        from core.recommendations import basis_lost_warning
        c = _claim(case, "A beacon ran on WS01.", host="WS01", confidence="CONFIRMED")
        rid = cg.add_recommendation(case, action="Isolate WS01 from the network", phase="contain", scope="host",
                                    urgency="now", basis_ids=[c])["node_id"]
        assert cg.supersede(case, c, reason="the beacon was the backup agent's heartbeat")["success"]
        cat = build_catalog(case)
        row = next(r for r in cat["recommendations"] if r["id"] == rid)
        assert row["basis_lost"] and row["basis_confidence"] == "UNCONFIRMED"
        assert do_now(cat) == []
        text = "\n".join(render_markdown(cat, "en"))
        assert "### Rests on withdrawn findings — review before acting" in text
        assert "backup agent's heartbeat" in text and "### Do now" not in text
        assert rid in basis_lost_warning(case)
        cg.set_recommendation_state(case, rid, "dismissed", actor="analyst", note="the finding was withdrawn")
        assert basis_lost_warning(case) == ""


def load_graph_rec(case, rid):
    return cg.load_graph(case)["nodes"][rid]
