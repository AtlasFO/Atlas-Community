"""What the analyst already knows earns first-hour precautions — recorded
as prior knowledge, in the case's language, never twice, never as findings.
The two universal precautions are recorded even with no intake at all, and
grading a case never withholds a recommendation (only indicator seeding)."""
import json

import pytest

from core import claim_graph as cg
from core import ir_playbook
from core.recommendations import build_catalog, report_readiness_advisories


def _case(tmp_path, intake: str | None, language: str = "en"):
    d = tmp_path / "CASE"
    (d / ".atlas").mkdir(parents=True)
    body = "# Case: CASE\n\n**Case ID:** CASE\n\n## Investigation Requests\n- What happened?\n"
    if intake is not None:
        body += f"\n## What you already know\n{intake}\n"
    (d / "CASE.md").write_text(body, encoding="utf-8")
    if language != "en":
        from core.case_config import set_report_language
        set_report_language(d, language)
    return d


class TestClassification:
    def test_classes_are_named_by_behaviour_words(self):
        assert ir_playbook.classify("files got encrypted and a ransom note appeared") == ["ransomware"]
        assert "credential_compromise" in ir_playbook.classify("an account may be compromised after phishing")
        assert ir_playbook.classify("data was exfiltrated to an unknown host") == ["exfiltration"]
        assert "domain_compromise" in ir_playbook.classify("PsExec against the domain controller")

    def test_a_compromised_host_is_not_a_credential_case(self):
        assert "credential_compromise" not in ir_playbook.classify("the host is compromised")

    def test_several_accounts_and_an_address_between_the_words_still_count(self):
        assert "credential_compromise" in ir_playbook.classify(
            "Both accounts are considered as compromised")
        assert "credential_compromise" in ir_playbook.classify(
            "The account first.last@example.test is considered compromised")
        assert "credential_compromise" in ir_playbook.classify(
            "Beide Konten gelten als kompromittiert")

    def test_german_intake_is_understood(self):
        assert ir_playbook.classify("Dateien wurden verschlüsselt, Lösegeld gefordert") == ["ransomware"]

    def test_steps_come_in_the_case_language_and_never_repeat(self):
        en = ir_playbook.baseline_steps("ransomware and phishing", "en")
        de = ir_playbook.baseline_steps("ransomware and phishing", "de")
        assert len(en) == len(de) and len({s["action"] for s in en}) == len(en)
        assert any("Isolate" in s["action"] for s in en)
        assert any("vom Netz trennen" in s["action"] for s in de)
        assert en[-1]["class"] == "universal"

    def test_an_intake_matching_no_class_still_gets_the_universal_precautions(self):
        steps = ir_playbook.baseline_steps("something odd on a laptop", "en")
        assert [s["class"] for s in steps] == ["universal", "universal"]


class TestSeeding:
    def test_precautions_are_recorded_as_prior_knowledge(self, tmp_path):
        case = _case(tmp_path, "We suspect ransomware on the file server.")
        out = ir_playbook.seed_from_intake(case)
        assert out["classes"] == ["ransomware"] and len(out["seeded"]) >= 5
        rows = build_catalog(case)["recommendations"]
        assert rows and all(r["source"] == "prior_knowledge" for r in rows)
        assert all(r["basis"] == [] and r["basis_confidence"] == "PRIOR" for r in rows)
        assert all(n["kind"] != "claim" for n in cg.load_graph(case)["nodes"].values())

    def test_seeding_twice_adds_nothing(self, tmp_path):
        case = _case(tmp_path, "ransomware")
        first = ir_playbook.seed_from_intake(case)["seeded"]
        again = ir_playbook.seed_from_intake(case)["seeded"]
        assert first and again == []
        assert build_catalog(case)["total"] == len(first)

    def test_the_language_follows_the_case(self, tmp_path):
        case = _case(tmp_path, "Ransomware, Dateien verschlüsselt", language="de")
        ir_playbook.seed_from_intake(case)
        actions = [r["action"] for r in build_catalog(case)["recommendations"]]
        assert any("vom Netz trennen" in a for a in actions)
        assert not any("Isolate affected" in a for a in actions)

    def test_no_intake_still_seeds_the_universal_precautions(self, tmp_path):
        case = _case(tmp_path, None)
        out = ir_playbook.seed_from_intake(case)
        assert not out["present"] and out["classes"] == [] and len(out["seeded"]) == 2
        rows = build_catalog(case)["recommendations"]
        assert len(rows) == 2
        assert all(r["source"] == "prior_knowledge" and r["basis_confidence"] == "PRIOR"
                   for r in rows)

    def test_a_graded_case_still_gets_recommendations(self, tmp_path):
        case = _case(tmp_path, "ransomware")
        (case / "ground_truth.json").write_text(json.dumps({"answers": []}), encoding="utf-8")
        out = ir_playbook.seed_from_intake(case)
        assert out["classes"] == ["ransomware"] and len(out["seeded"]) >= 5
        assert build_catalog(case)["total"] == len(out["seeded"])


class TestReadinessAdvisory:
    def _claim(self, case, host):
        return cg.add_claim(case, statement=f"something on {host}", confidence="CONFIRMED",
                            host=host)["node_id"]

    def test_findings_without_any_recommendation_are_called_out(self, tmp_path):
        case = _case(tmp_path, None)
        self._claim(case, "A")
        msgs = report_readiness_advisories(case, ["A"], 1)
        assert len(msgs) == 1 and "no recommendation rests on any" in msgs[0]

    def test_prior_knowledge_alone_does_not_count_as_a_plan(self, tmp_path):
        case = _case(tmp_path, "ransomware")
        ir_playbook.seed_from_intake(case)
        self._claim(case, "A")
        assert report_readiness_advisories(case, ["A"], 1)

    def test_host_only_measures_on_a_multi_host_case_are_called_out(self, tmp_path):
        case = _case(tmp_path, None)
        a, b = self._claim(case, "A"), self._claim(case, "B")
        cg.add_recommendation(case, action="Isolate A", phase="contain", basis_ids=[a])
        msgs = report_readiness_advisories(case, ["A", "B"], 2)
        assert len(msgs) == 1 and "host-scoped" in msgs[0]
        cg.add_recommendation(case, action="Reset every domain credential", phase="eradicate",
                              scope="estate", basis_ids=[a, b])
        assert report_readiness_advisories(case, ["A", "B"], 2) == []

    def test_no_substantiated_findings_means_no_advisory(self, tmp_path):
        case = _case(tmp_path, None)
        assert report_readiness_advisories(case, [], 0) == []


class TestAssertedClassification:
    """A finding names artefacts. Read as a finding, a class must be
    asserted (the class noun near an act, or a word that is the behaviour
    itself); a mention alone earns no precaution."""

    def test_a_password_tool_in_a_listing_is_not_a_credential_compromise(self):
        s = "12 shortcuts to attack tools: Cain v2.5 (password recovery), CuteFTP, Ethereal"
        assert "credential_compromise" in ir_playbook.classify(s)
        assert ir_playbook.classify(s, asserted=True) == []

    def test_dumped_or_sprayed_credentials_are(self):
        assert "credential_compromise" in ir_playbook.classify(
            "NTDS.dit was dumped and domain credentials harvested", asserted=True)
        assert "credential_compromise" in ir_playbook.classify(
            "Password spraying against the VPN portal from 203.0.113.9", asserted=True)
        assert "credential_compromise" in ir_playbook.classify(
            "Beide Konten gelten als kompromittiert", asserted=True)

    def test_encrypted_traffic_is_not_ransomware_but_encrypted_files_are(self):
        assert ir_playbook.classify("TLS-encrypted traffic to 10.0.0.5 observed", asserted=True) == []
        assert ir_playbook.classify(
            "User files on the share were encrypted and a ransom note dropped", asserted=True) == ["ransomware"]

    def test_a_domain_controller_that_exists_is_not_a_domain_compromise(self):
        assert ir_playbook.classify("A domain controller DC01 exists in the estate", asserted=True) == []
        assert "domain_compromise" in ir_playbook.classify(
            "PsExec launched from WS01 against the domain controller", asserted=True)

    def test_an_employee_profile_is_not_an_insider_case(self):
        assert ir_playbook.classify("The employee profile contains Outlook Express folders", asserted=True) == []
        assert ir_playbook.classify(
            "The former employee copied the client list to a USB drive", asserted=True) == ["insider"]

    def test_an_upload_of_an_archive_is_exfiltration_and_a_bare_leak_is_not(self):
        assert ir_playbook.classify("Archive finance.7z uploaded to mega.nz over HTTPS", asserted=True) == ["exfiltration"]
        assert ir_playbook.classify("The driver has a memory leak", asserted=True) == []

    def test_a_detection_is_still_malware(self):
        assert ir_playbook.classify("ClamAV detected Win.Trojan.Cain-9 in Abel.dll", asserted=True) == ["malware"]

    def test_intake_reading_is_unchanged(self):
        assert "credential_compromise" in ir_playbook.classify("the attacker had the admin password")
        steps = ir_playbook.baseline_steps("stolen passwords", "en", asserted=True)
        assert any(s["class"] == "credential_compromise" for s in steps)


class TestSuspectDevice:
    """The device of the person under investigation, examined after the
    fact, has no owner to advise: the intake seeds no precaution, and
    precautions seeded before the brief said so are dismissed. Seized
    running, it gets acquisition steps only. A victim's system keeps every
    precaution after the fact, because its owner's live estate is what the
    precautions protect."""

    def _with_rows(self, d, engagement="examination", owner="suspect"):
        text = (d / "CASE.md").read_text(encoding="utf-8")
        rows = "**Case ID:** CASE\n"
        if engagement:
            rows += f"**Engagement:** {engagement}\n"
        if owner:
            rows += f"**System owner:** {owner}\n"
        (d / "CASE.md").write_text(text.replace("**Case ID:** CASE\n", rows), encoding="utf-8")
        return d

    def test_no_precaution_is_seeded_after_the_fact(self, tmp_path):
        d = self._with_rows(_case(tmp_path, "We suspect ransomware; files were encrypted."))
        r = ir_playbook.seed_from_intake(d)
        assert r["seeded"] == [] and "suspect" in r["skipped"]
        assert "ransomware" in r["classes"]
        assert build_catalog(d)["total"] == 0

    def test_precautions_seeded_before_the_rows_are_dismissed(self, tmp_path):
        d = _case(tmp_path, "We suspect ransomware; files were encrypted.")
        seeded = ir_playbook.seed_from_intake(d)["seeded"]
        assert seeded
        self._with_rows(d)
        r = ir_playbook.seed_from_intake(d)
        assert sorted(r["dismissed"]) == sorted(seeded)
        rows = {x["id"]: x for x in build_catalog(d)["recommendations"]}
        assert all(rows[i]["state"] == "dismissed" for i in seeded)

    def test_a_seized_running_device_gets_acquisition_steps_only(self, tmp_path):
        d = self._with_rows(_case(tmp_path, "We suspect ransomware; files were encrypted."),
                            engagement="incident-response")
        # Without a live evidence entry the device is an image: no seizure step.
        r0 = ir_playbook.seed_from_intake(d)
        assert not any("without powering it off" in x["action"] for x in build_catalog(d)["recommendations"])
        from core.evidence_links import empty_links, save_evidence_links
        links = empty_links("X")
        links["entries"].append({"label": "LAPTOP", "kind": "live", "path": "", "host": "LAPTOP"})
        save_evidence_links(d, links)
        r = ir_playbook.seed_from_intake(d)
        assert r["seeded"] and not r.get("skipped")
        rows = build_catalog(d)["recommendations"]
        actions = [x["action"] for x in rows]
        assert any("without powering it off" in a for a in actions)
        assert any("timestamped record" in a for a in actions)
        # The seizure step covers the device's memory; the estate-wide
        # precaution belongs to the incident frame, where the owner's
        # systems are still running.
        assert not any("Preserve volatile state" in a for a in actions)
        assert not any("ransom" in a.lower() or "backup" in a.lower() for a in actions)
        assert all(x["rationale"].startswith(ir_playbook.PRECAUTION_RATIONALE_PREFIXES) for x in rows)
        # Once the brief says the device is examined after the fact, the
        # acquisition rows are dismissed like any other precaution.
        self._with_rows(d)
        assert sorted(ir_playbook.seed_from_intake(d)["dismissed"]) == sorted(r["seeded"] + r0["seeded"])

    def test_a_victim_examined_after_the_fact_is_seeded_as_a_live_incident(self, tmp_path):
        after = self._with_rows(_case(tmp_path, "We suspect ransomware; files were encrypted."),
                                owner="victim")
        live = _case(tmp_path / "live", "We suspect ransomware; files were encrypted.")
        a = ir_playbook.seed_from_intake(after)
        b = ir_playbook.seed_from_intake(live)
        assert a["seeded"] and not a.get("skipped")
        key = lambda cat: sorted((x["action"], x["phase"], x["urgency"], x["scope"])
                                 for x in cat["recommendations"])
        assert key(build_catalog(after)) == key(build_catalog(live))

    def test_an_incident_is_seeded_as_before(self, tmp_path):
        d = _case(tmp_path, "We suspect ransomware; files were encrypted.")
        assert ir_playbook.seed_from_intake(d)["seeded"]


# ── negation, clause-scoped ──────────────────────────────────────────────

_NEGATED_CLASS_CASES = [
    ("No ransomware was found and no files were encrypted.", []),
    ("There is no indication that data was exfiltrated.", []),
    ("No credentials were dumped.", []),
    ("Credentials were not dumped and files were not encrypted.", []),
    ("The user wasn't involved; credentials weren't dumped.", []),
    ("Keine Hinweise auf Ransomware gefunden.", []),
    ("Es wurden keine Daten exfiltriert.", []),
    ("Mimikatz dumped the credentials of three admins, but no lateral movement was found.",
     ["credential_compromise"]),
    ("Ransomware encrypted the file share; no backups were found.", ["ransomware"]),
    ("The attacker dumped LSASS credentials and no exfiltration was observed.",
     ["credential_compromise"]),
    ("No EDR alert fired while the attacker dumped LSASS credentials.", ["credential_compromise"]),
    ("The actor not only exfiltrated the data but also encrypted it.", ["ransomware", "exfiltration"]),
    ("Exfiltration was not observed.", []),
    ("Data exfiltration to Mega was not observed.", []),
    ("Die Zugangsdaten wurden ausgelesen, ein Datenabfluss wurde nicht festgestellt.",
     ["credential_compromise"]),
    ("The attacker has not yet exfiltrated the data.", []),
    ("Nothing was exfiltrated.", []),
    ("Nobody dumped the credentials.", []),
    ("Nichts wurde exfiltriert.", []),
    ("Niemand hat Zugangsdaten ausgelesen.", []),
    ("The attacker dumped credentials, yet no data left the network.", ["credential_compromise"]),
]


class TestNegatedClauses:
    """A class word in a negated clause asserts nothing; the scope is the
    clause, so a positive clause beside a negative one still asserts."""

    @pytest.mark.parametrize("statement, want", _NEGATED_CLASS_CASES)
    def test_finding_classes_honour_negation(self, statement, want):
        got = [c for c in ir_playbook.classify(statement, asserted=True)
               if c not in ir_playbook.MANDATORY_CLASSES]
        assert sorted(got) == sorted(want), statement

    def test_a_contrast_word_ends_the_negated_clause(self):
        low = "no files were encrypted, but the notes were dropped"
        a = low.index("dropped")
        assert ir_playbook.negated(low, a, a + len("dropped")) is False
        b = low.index("encrypted")
        assert ir_playbook.negated(low, b, b + len("encrypted")) is True

    def test_not_only_does_not_negate(self):
        low = "the actor not only encrypted the files"
        assert ir_playbook.negated(low, low.index("encrypted"), low.index("encrypted") + 9) is False


# ── mandatory escalation ─────────────────────────────────────────────────

_ESCALATION_CASES = [
    ("No weapons were found on the laptop, but the chats show he planned a shooting at the school.",
     ["violence"]),
    ("He did not hide his plans for a shooting at the school.", ["violence"]),
    ("The manifesto describes the planned bombing of the station.", ["violence"]),
    ("The user threatened to shoot his manager.", ["violence"]),
    ("Er plant einen Anschlag auf die Schule.", ["violence"]),
    ("Er plante einen Anschlag auf die Schule.", ["violence"]),
    ("Die Chats belegen den geplanten Anschlag auf die Schule.", ["violence"]),
    ("Er hatte Pläne für einen Amoklauf.", ["violence"]),
    ("Er plant einen Anschlag, Waffen wurden keine gefunden.", ["violence"]),
    ("Die Anschlagspläne lagen im Ordner Dokumente.", ["violence"]),
    ("Der Täter drohte mit einem Amoklauf.", ["violence"]),
    ("Die Logikbombe war für Freitag geplant.", []),
    ("Eine ZIP-Bombe wurde vorbereitet.", []),
    ("Eine Bedrohungsanalyse wurde vorbereitet.", []),
    ("The attacker planted a web shell on the target.", []),
    ("He has not yet planned a shooting.", []),
    ("He showed no remorse and planned a shooting.", ["violence"]),
    ("The device held CSAM; no distribution was found.", ["csam"]),
    ("Images of the missing child were identified as child sexual abuse material.", ["csam"]),
    ("The folder contains only CSAM.", ["csam"]),
    ("No evidence of planned violence was found on the device.", []),
    ("There is no indication that he planned a shooting.", []),
    ("Keine Hinweise auf einen geplanten Anschlag gefunden.", []),
    ("No CSAM was found on the device.", []),
    ("keine Drohung, keinen Anschlag geplant", []),
    ("The user didn't plan any violence.", []),
    ("The insider planned a logic bomb to wipe the file server.", []),
    ("The attacker prepared an MFA push bombing campaign against the admins.", []),
    ("The actor planned an email bombing to bury the bank's transfer notifications.", []),
    ("A zip bomb was prepared to crash the mail scanner.", []),
    # ordinary intrusion prose never reads as planned violence
    ("The threat actor killed the Defender process (MsMpEng.exe) on the target host with taskkill.", []),
    ("A weaponized Word document targeted the finance team via spear-phishing.", []),
    ("The attacker prepared a weaponized payload and targeted the domain controller.", []),
    ("Kill chain: initial access via RDP brute force against the target DC01.", []),
    ("The ransomware operator planned to kill the backup services before encryption.", []),
    ("The malware's kill switch domain was contacted; the target list included 50 hosts.", []),
    ("The actor terminated the EDR agent with a kill command on every targeted server.", []),
    ("Der Angreifer beendete den Virenscanner mit taskkill auf dem Zielsystem.", []),
    ("Die Bedrohung zielte auf die Domänencontroller; der Dienst wurde gekillt.", []),
    ("Threat intelligence attributes the tooling to a group with terror-financing links.", []),
    ("The threat actor exploited CVE-2021-44228 (Log4Shell) and shot a web shell onto the target.", []),
]


class TestMandatoryEscalation:
    """Planned violence, abuse material and extortion are escalated whatever
    the owner and the engagement, are never dismissed, and lead the plan."""

    @pytest.mark.parametrize("statement, want", _ESCALATION_CASES)
    def test_the_classes_fire_on_asserted_harm_only(self, statement, want):
        got = [c for c in ir_playbook.classify(statement, asserted=True)
               if c in ("violence", "csam")]
        assert sorted(got) == sorted(want), statement

    @pytest.mark.parametrize("statement, want", _ESCALATION_CASES)
    def test_the_intake_reading_agrees(self, statement, want):
        got = [c for c in ir_playbook.classify(statement) if c in ("violence", "csam")]
        assert sorted(got) == sorted(want), statement

    def test_extortion_reads_in_both_languages_with_negation(self):
        assert "extortion" in ir_playbook.classify("The chats show the user blackmailed a classmate", asserted=True)
        assert "extortion" in ir_playbook.classify("Der Nutzer erpresste eine Mitschülerin", asserted=True)
        assert "extortion" not in ir_playbook.classify("No extortion was found in the chats", asserted=True)

    def _brief(self, tmp_path, intake, owner="suspect", engagement="examination"):
        d = _case(tmp_path, intake)
        text = (d / "CASE.md").read_text(encoding="utf-8")
        rows = "**Case ID:** CASE\n"
        if engagement:
            rows += f"**Engagement:** {engagement}\n"
        if owner:
            rows += f"**System owner:** {owner}\n"
        (d / "CASE.md").write_text(text.replace("**Case ID:** CASE\n", rows), encoding="utf-8")
        return d

    def test_the_intake_seeds_the_escalation_on_the_suspects_device(self, tmp_path):
        d = self._brief(tmp_path, "The user is suspected of planning a violent attack.")
        r = ir_playbook.seed_from_intake(d)
        rows = build_catalog(d)["recommendations"]
        assert r["seeded"] and len(rows) == 2
        assert all(x["mandatory"] and x["urgency"] == "now" and x["phase"] == "escalate" for x in rows)
        assert all(x["rationale"].startswith(ir_playbook.MANDATORY_RATIONALE_PREFIX) for x in rows)
        assert any("law enforcement" in x["action"] for x in rows)
        # seeding again dismisses nothing and adds nothing
        again = ir_playbook.seed_from_intake(d)
        assert again["seeded"] == [] and again["dismissed"] == []
        assert all(x["state"] == "open" for x in build_catalog(d)["recommendations"])

    def test_a_negated_intake_seeds_nothing_mandatory(self, tmp_path):
        d = self._brief(tmp_path, "No indication of planned violence; the device is examined for fraud.")
        ir_playbook.seed_from_intake(d)
        assert not any(x["mandatory"] for x in build_catalog(d)["recommendations"])

    def test_a_finding_derives_the_escalation_whatever_the_owner(self, tmp_path):
        from core.recommendations import derive_from_finding_text
        d = self._brief(tmp_path, "Examination of a seized laptop.")
        c = cg.add_claim(d, statement="Planning.docx describes the planned shooting at the airport",
                         confidence="LIKELY", host="LAPTOP")["node_id"]
        out = derive_from_finding_text(d, c, "Planning.docx describes the planned shooting at the airport",
                                       host="LAPTOP")
        assert out["recorded"] and "skipped" in out
        rows = build_catalog(d)["recommendations"]
        assert rows and all(x["mandatory"] for x in rows)
        assert rows[0]["basis"][0]["id"] == c
        assert not any("Isolate" in x["action"] for x in rows)

    def test_an_intrusion_finding_derives_no_escalation(self, tmp_path):
        from core.recommendations import derive_from_finding_text
        d = _case(tmp_path, "")
        c = cg.add_claim(d, statement="The ransomware operator planned to kill the backup services before encrypting the files on the share",
                         confidence="LIKELY", host="FS01")["node_id"]
        derive_from_finding_text(d, c, "The ransomware operator planned to kill the backup services before encrypting the files on the share", host="FS01")
        assert not any(x["mandatory"] for x in build_catalog(d)["recommendations"])

    def test_mandatory_rows_lead_the_plan_and_survive_the_owner_rule(self, tmp_path):
        d = _case(tmp_path, "We suspect ransomware; files were encrypted.")
        ir_playbook.seed_from_intake(d)
        cg.add_recommendation(d, action="Escalate the indications of planned violence to law enforcement now",
                              phase="escalate", scope="estate", urgency="now",
                              source="prior_knowledge", mandatory=True,
                              rationale=f"{ir_playbook.MANDATORY_RATIONALE_PREFIX}: violence, from the case intake")
        rows = build_catalog(d)["recommendations"]
        assert rows[0]["mandatory"] and "law enforcement" in rows[0]["action"]
        # the brief now says the device is the suspect's: every precaution
        # is dismissed, the escalation stays
        text = (d / "CASE.md").read_text(encoding="utf-8")
        (d / "CASE.md").write_text(text.replace("**Case ID:** CASE\n",
                                                "**Case ID:** CASE\n**Engagement:** examination\n**System owner:** suspect\n"),
                                   encoding="utf-8")
        r = ir_playbook.seed_from_intake(d)
        assert r["dismissed"]
        rows = build_catalog(d)["recommendations"]
        assert [x for x in rows if x["state"] == "open"] == [x for x in rows if x["mandatory"]]

    def test_extortion_steps_follow_the_frame(self):
        inc = [s["action"] for s in ir_playbook.baseline_steps("The victim was extorted by mail", asserted=True)
               if s["class"] == "extortion"]
        sub = [s["action"] for s in ir_playbook.baseline_steps("The user extorted a classmate by mail",
                                                               asserted=True, subject=True)
               if s["class"] == "extortion"]
        assert inc and all("legal counsel" in a for a in inc)
        assert any("being extorted" in a for a in sub) and not any("legal counsel" in a for a in sub)

    def test_german_steps(self):
        steps = ir_playbook.baseline_steps("Er plante einen Anschlag auf die Schule.", "de", asserted=True)
        assert any("Strafverfolgungsbehörden" in s["action"] for s in steps if s["class"] == "violence")


    def test_a_mandatory_row_is_closed_with_a_note_and_never_dismissed(self, tmp_path):
        d = self._brief(tmp_path, "The user is suspected of planning a violent attack.")
        ir_playbook.seed_from_intake(d)
        row = build_catalog(d)["recommendations"][0]
        assert row["mandatory"]
        r = cg.set_recommendation_state(d, row["id"], "dismissed", actor="examiner")
        assert not r["success"] and r["gate"] == "mandatory_escalation"
        r = cg.set_recommendation_state(d, row["id"], "done", actor="examiner", note="ok")
        assert not r["success"] and "note" in r["error"]
        r = cg.set_recommendation_state(d, row["id"], "done", actor="examiner",
                                        note="Reported to the duty officer, reference recorded in the case file")
        assert r["success"]
        rows = build_catalog(d)["recommendations"]
        done = next(x for x in rows if x["id"] == row["id"])
        assert done["state"] == "done" and done["state_note"].startswith("Reported to the duty officer")
        from core.recommendations import render_markdown
        text = "\n".join(render_markdown(build_catalog(d)))
        assert "Reported to the duty officer" in text
        # an ordinary row still dismisses without a note
        plain = cg.add_recommendation(d, action="Review the sync client logs", phase="contain",
                                      source="prior_knowledge")
        assert cg.set_recommendation_state(d, plain["node_id"], "dismissed")["success"]


class TestReviewedEscalationMechanics:
    @pytest.mark.parametrize("statement", [
        "The folder held indecent images of children.",
        "The examiner identified IIOC on the second partition.",
        "The share carried child sexual exploitation material (CSEM).",
        "Die Dateien sind jugendpornografische Aufnahmen.",
    ])
    def test_the_standard_terms_for_abuse_material_fire(self, statement):
        assert "csam" in ir_playbook.classify(statement, asserted=True)

    def test_a_negated_term_does_not_fire(self):
        assert "csam" not in ir_playbook.classify("No indecent images of children were found.", asserted=True)

    def test_a_negated_intake_seeds_no_class(self):
        assert "ransomware" not in ir_playbook.classify("No ransomware was found; the alert was a false positive.")

    def test_the_suspicion_in_a_metadata_row_seeds_the_escalation(self, tmp_path):
        d = tmp_path / "CASE"
        (d / ".atlas").mkdir(parents=True)
        (d / "CASE.md").write_text(
            "# Case: X\n\n| Field | Value |\n|---|---|\n| **Case ID** | X |\n| **Engagement** | examination |\n"
            "| **System owner** | suspect |\n| **Scenario** | A laptop is seized; the user is suspected of planning "
            "a violent attack. |\n\n## Investigation Requests\n- Who used the laptop?\n", encoding="utf-8")
        r = ir_playbook.seed_from_intake(d)
        rows = build_catalog(d)["recommendations"]
        assert r["seeded"] and rows and all(x["mandatory"] for x in rows)

    def test_a_mandatory_step_folds_across_scopes_and_new_evidence_after_closure_opens_a_new_row(self, tmp_path):
        from core.recommendations import derive_from_finding_text
        d = tmp_path / "CASE"
        (d / ".atlas").mkdir(parents=True)
        (d / "CASE.md").write_text("# Case: X\n\n**Case ID:** X\n**System owner:** suspect\n\n"
                                   "## What you already know\nThe user is suspected of planning a violent attack.\n",
                                   encoding="utf-8")
        seeded = ir_playbook.seed_from_intake(d)["seeded"]
        assert seeded
        text = "Planning.docx describes the planned shooting at the station"
        c = cg.add_claim(d, statement=text, confidence="LIKELY", host="LAPTOP")["node_id"]
        # while the seeded rows are open, the finding folds into them across scopes
        out = derive_from_finding_text(d, c, text, host="LAPTOP")
        rows = {x["id"]: x for x in build_catalog(d)["recommendations"]}
        mandatory = sorted(r for r in seeded if rows[r]["mandatory"])
        assert mandatory and out["recorded"] == [] and sorted(out["folded"]) == mandatory
        assert all(c in [b["id"] for b in rows[r]["basis"]] for r in mandatory)
        for rid in seeded:
            assert cg.set_recommendation_state(d, rid, "done", note="Reported to the duty officer today")["success"]
        # the same indication again: folds, the closed rows keep their state
        out = derive_from_finding_text(d, c, text, host="LAPTOP")
        assert out["recorded"] == [] and sorted(out["folded"]) == mandatory
        # new evidence after closure: a new open mandatory row, the closed rows untouched
        c2 = cg.add_claim(d, statement="The chats describe the planned bombing of the station",
                          confidence="LIKELY", host="LAPTOP")["node_id"]
        out = derive_from_finding_text(d, c2, "The chats describe the planned bombing of the station", host="LAPTOP")
        rows = {x["id"]: x for x in build_catalog(d)["recommendations"]}
        assert out["recorded"] and all(rows[r]["mandatory"] and rows[r]["state"] == "open" for r in out["recorded"])
        assert all(rows[r]["state"] == "done" and c2 not in [b["id"] for b in rows[r]["basis"]] for r in mandatory)

    def test_an_ordinary_row_absorbing_a_mandatory_step_becomes_mandatory(self, tmp_path):
        d = tmp_path / "CASE"
        (d / ".atlas").mkdir(parents=True)
        (d / "CASE.md").write_text("# Case: X\n\n**Case ID:** X\n", encoding="utf-8")
        c = cg.add_claim(d, statement="Planning.docx describes the planned shooting at the station",
                         confidence="LIKELY", host="LAPTOP")["node_id"]
        plain = cg.add_recommendation(d, action="Escalate the indications of planned violence to law enforcement now",
                                      phase="escalate", scope="host", urgency="now", basis_ids=[c])["node_id"]
        assert cg.set_recommendation_state(d, plain, "dismissed")["success"]
        from core.recommendations import derive_from_finding_text
        derive_from_finding_text(d, c, "Planning.docx describes the planned shooting at the station", host="LAPTOP")
        node = cg.get_node(cg.load_graph(d), plain)
        assert node["mandatory"] is True
        assert not cg.set_recommendation_state(d, plain, "dismissed")["success"]
