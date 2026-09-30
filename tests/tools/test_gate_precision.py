"""Gates refuse on what the analyst claims, not on what the evidence or the
grammar around it happens to contain: quoted source text is not the
analyst's quantifier, a folder in a path is not a person, a parser's
output kept on disk still names the artifacts it read, and a sentence that
denies egress needs no transfer artifact."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from tools._gates import GateContext
from tools._gates import principal_attribution_grounding as pag
from tools._gates import exfil_channel_grounding as ecg
from tools._gates import hypothesize_required as hyp
from tools._gates import lineage_relevance as lr
from tools._gates import named_actor_attribution_grounding as nag
from tools._gates import universal_from_truncated as uft


def _ctx(description, *, tier="LIKELY", supporting_evidence="", linked_call_id=0,
         input_call_ids=None, by_call_id=None, by_type=None, lineage_inferred=False):
    return GateContext(
        description=description, confidence=tier.capitalize(), tier=tier, source="test",
        linked_call_id=linked_call_id, tested_hypothesis_id="", log=MagicMock(),
        idx=SimpleNamespace(by_call_id=by_call_id or {}, by_type=by_type or {}),
        window=[], input_call_ids=input_call_ids or [],
        supporting_evidence=supporting_evidence, lineage_inferred=lineage_inferred)


class TestQuotedTextIsNotTheAnalystsQuantifier:
    def test_universal_words_inside_a_quotation_do_not_count(self):
        assert not uft.is_universal_or_negative(
            "The thread reads: sender 'It is very hard to transfer all data over the "
            "internet!'; reply 'No problem. Deliver storage devices.'")

    def test_the_analysts_own_universal_still_counts(self):
        assert uft.is_universal_or_negative(
            "'Hello, Iaman' and all subsequent requests came from the same sender")

    def test_a_possessive_is_not_a_quotation(self):
        # An apostrophe inside a word must not open a "quotation" that
        # swallows the analyst's own words up to the next apostrophe.
        assert uft.is_universal_or_negative(
            "the subject's own account is user1; all messages to it were deleted")

    def test_a_cut_view_no_longer_refuses_a_finding_quoting_the_evidence(self):
        cut = {"type": "tool_call", "cmd": "<py>:strings_read_text", "view_truncated": True,
               "view_omitted_chars": 500, "evidence_ref": "mnt/host/fs/Users/u/mail.ost",
               "stdout_excerpt": "Stop it! It is very hard to transfer all data"}
        ctx = _ctx("The mail.ost thread shows the reply 'It is very hard to transfer all "
                   "data over the internet' on 24 Mar", by_call_id={61: cut},
                   input_call_ids=[61])
        assert uft.check(ctx) is None


class TestNamedActorExtraction:
    def test_a_folder_segment_is_not_a_person(self):
        out = nag.check(_ctx(
            "Two sample files were uploaded from the local sync folder "
            "C:\\Users\\informant\\Google Drive to the personal cloud account"))
        assert out is None

    def test_a_domain_qualified_name_still_is(self):
        out = nag.check(_ctx("CORP\\Alice copied the archive to the USB stick"))
        assert out is not None and "Alice" in out["error"]

    def test_the_subject_cue_reads_only_a_capitalised_name(self):
        by_type = {"dair_call": [{"inputs": {"case_context": (
            "the subject placed sample files; subject activity on the host; "
            "Subject: Dana")}}]}
        assert nag._case_subject_names(_ctx("x", by_type=by_type)) == {"Dana"}


class TestCitedCallsAreJudgedWithTheirSpilledOutput:
    def test_the_artifact_named_past_the_excerpt_is_still_seen(self, tmp_path):
        spill = tmp_path / "pecmd.stdout"
        spill.write_text("\n".join(f"row {i} FILLER.EXE-{i:04X}.pf" for i in range(300))
                         + "\nERASER.EXE-1A2B3C4D.pf run 3 times\n", encoding="utf-8")
        call = {"type": "tool_call", "call_id": 30, "success": True,
                "cmd": "dotnet PECmd.dll -d mnt/host/fs/Windows/Prefetch",
                "stdout_excerpt": "row 0 FILLER.EXE-0000.pf", "stdout_file": str(spill)}
        ctx = _ctx("Prefetch shows ERASER.EXE was run three times", by_call_id={30: call},
                   input_call_ids=[30], linked_call_id=30)
        assert lr.check(ctx) is None

    def test_without_the_file_the_call_looks_unrelated(self):
        call = {"type": "tool_call", "call_id": 30, "success": True,
                "cmd": "dotnet PECmd.dll -d mnt/host/fs/Windows/Prefetch",
                "stdout_excerpt": "row 0 FILLER.EXE-0000.pf"}
        ctx = _ctx("Prefetch shows ERASER.EXE was run three times", by_call_id={30: call},
                   input_call_ids=[30], linked_call_id=30)
        assert lr.check(ctx) is not None


class TestDeniedEgressNeedsNoTransferArtifact:
    def test_a_claim_that_nothing_was_exfiltrated_over_the_channel_passes(self):
        out = ecg.check(_ctx(
            "The unauthorised USB stick holds only personal files; no confidential "
            "documents were exfiltrated via this removable medium",
            supporting_evidence="fls listing: photo1.jpg, song1.mp3"))
        assert out is None

    def test_a_positive_egress_claim_beside_a_denial_is_still_gated(self):
        out = ecg.check(_ctx(
            "No data was exfiltrated over USB; the documents were uploaded to the "
            "personal cloud account instead",
            supporting_evidence="sync folder listing: report.docx"))
        assert out is not None and out["gate"] == "exfil_channel_grounding"

    def test_asserts_egress_reads_sentence_by_sentence(self):
        assert not ecg.asserts_egress("nothing was uploaded; no files were transferred")
        assert ecg.asserts_egress("nothing was deleted. The archive was uploaded to the share")


class TestHedgesAreNotClaimsAboutRows:
    def test_an_inability_to_conclude_is_not_an_absence_claim(self):
        assert not uft.is_universal_or_negative(
            "The second-principal question cannot be confirmed or refuted from the "
            "available evidence; the controller could not be determined")
        assert not uft.is_universal_or_negative("none can be excluded on current evidence")

    def test_an_observation_that_was_not_made_is_still_a_claim_about_the_evidence(self):
        assert uft.is_universal_or_negative("the password was not found in the dump")
        assert uft.is_universal_or_negative("no logon for the account was recorded")

    def test_a_parked_hypothesis_may_cite_a_truncated_call(self):
        cut = {"type": "tool_call", "cmd": "sudo ngrep -q -I evidence/network/capture.pcap POST",
               "truncated": True, "stdout_excerpt": "T 10.0.0.5 -> 203.0.113.9:443 POST /x"}
        ctx = _ctx("Controller unknown: a second principal cannot be confirmed or excluded on "
                   "the evidence collected", tier="UNCONFIRMED", by_call_id={7: cut},
                   input_call_ids=[7])
        assert uft.check(ctx) is None


class TestInferredLineageForNegativeClaims:
    """When the analyst cites nothing, Atlas infers the lineage. A universal
    or negative claim is not handed a call the analyst saw only part of:
    that would be Atlas creating the objection universal_from_truncated
    then raises."""

    WINDOW = [
        {"type": "reason_call", "call_id": 4, "tool": "reason_hypothesize"},
        {"type": "tool_call", "call_id": 6, "cmd": "vol -f evidence/host.mem windows.info",
         "success": True, "stdout_excerpt": "Kernel Base"},
        {"type": "tool_call", "call_id": 7, "cmd": "sudo ngrep -q -I evidence/network/capture.pcap POST",
         "success": True, "truncated": True, "stdout_excerpt": "T 10.0.0.5 -> 203.0.113.9:443"},
    ]

    def test_a_negative_claim_is_not_given_an_incomplete_call(self):
        from tools import misc
        got = misc._infer_input_call_ids(
            self.WINDOW, description="No second principal was identified on the host")
        assert 7 not in got and got == [4, 6]

    def test_a_positive_claim_keeps_recency_as_before(self):
        from tools import misc
        got = misc._infer_input_call_ids(
            self.WINDOW, description="A POST to 203.0.113.9 was observed in the capture")
        assert got == [4, 6, 7]


class TestProtocolTransferEvidenceCountsAsATransferRecord:
    """A capture shows a transfer through the protocol's own exchange - the
    command that moves the file and the reply that opens its data
    connection - whatever the capture file is called. A directory listing
    over the same session is still only presence."""

    STOR = ("T 10.0.0.5:2000 -> 192.0.2.10:21 [AP] STOR archive.zip..\n"
            "T 192.0.2.10:21 -> 10.0.0.5:2000 [AP] 150 Opening BINARY mode data "
            "connection for archive.zip..")
    LS = ("total 1066..-rw-r--r-- 1 gnome staff 230566 Apr 26 2004 archive.zip..")
    CLAIM = ("The workstation at 10.0.0.5 uploaded archive.zip to the FTP server at "
             "192.0.2.10 under the account gnome")

    def _ctx(self, excerpt):
        call = {"type": "tool_call", "call_id": 274, "success": True,
                "cmd": "sudo ngrep -q -I evidence/session.log -i STOR|150 tcp",
                "stdout_excerpt": excerpt}
        return _ctx(self.CLAIM, tier="LIKELY", by_call_id={274: call}, input_call_ids=[274],
                    linked_call_id=274)

    def test_an_ftp_store_and_its_data_connection_reply_ground_the_upload(self):
        assert ecg.check(self._ctx(self.STOR)) is None

    def test_a_directory_listing_alone_is_still_presence(self):
        out = ecg.check(self._ctx(self.LS))
        assert out is not None and out["gate"] == "exfil_channel_grounding"

    def test_an_http_upload_request_grounds_a_web_upload(self):
        call = {"type": "tool_call", "call_id": 9, "success": True,
                "cmd": "sudo tcpdump -r evidence/capture.log -A tcp port 80",
                "stdout_excerpt": "POST /upload HTTP/1.1\r\nHost: files.example\r\nContent-Length: 440517\r\n"}
        ctx = _ctx("The workstation uploaded the archive to files.example over HTTP web upload",
                   tier="LIKELY", by_call_id={9: call}, input_call_ids=[9], linked_call_id=9)
        assert ecg.check(ctx) is None


class TestProgramsNamedLikePeopleAreNotActors:
    """A copula or a subject that binds to a name the cited evidence prints
    as a program (an executable stem, a directory under Program Files) binds
    software, not a person. A profile directory is not exempt: it is named
    after the person the gate asks about."""

    from tools._gates import principal_attribution_grounding as pag

    CLAM = {"type": "tool_call", "call_id": 5, "success": True,
            "cmd": "<py>:misc_clamscan_file",
            "stdout_excerpt": "C:\\Program Files\\Cain\\Abel.dll: Win.Trojan.Cain-9 FOUND"}

    def test_a_tool_named_like_a_person_does_not_need_a_session_artifact(self):
        ctx = _ctx("AV detection: ClamAV flagged Abel.dll; Abel is Cain's companion "
                   "password-recovery tool, flagged for its credential-grabbing routines",
                   tier="LIKELY", by_call_id={5: self.CLAM}, input_call_ids=[5], linked_call_id=5)
        assert self.pag.check(ctx) is None

    def test_a_person_bound_to_a_credential_still_needs_one(self):
        ctx = _ctx("The credential for the service account is Alice's, per the note",
                   tier="LIKELY", by_call_id={5: self.CLAM}, input_call_ids=[5], linked_call_id=5)
        assert self.pag.check(ctx) is not None

    def test_a_profile_directory_does_not_exempt_a_person(self):
        listing = {"type": "tool_call", "call_id": 6, "success": True,
                   "cmd": "fls -r -o 63 image.raw 344",
                   "stdout_excerpt": "d/d 3671: Documents and Settings\\Alice\\Desktop"}
        ctx = _ctx("The credential for the service account is Alice's", tier="LIKELY",
                   by_call_id={6: listing}, input_call_ids=[6], linked_call_id=6)
        assert self.pag.check(ctx) is not None

    def test_a_program_subject_is_not_an_actor_for_the_named_actor_gate(self):
        tools_dir = {"type": "tool_call", "call_id": 7, "success": True,
                     "cmd": "fls -r -o 63 image.raw 9000",
                     "stdout_excerpt": "r/r 9012: Desktop\\Tools\\Agent.lnk\nr/r 9013: Desktop\\Tools\\Cain.lnk"}
        ctx = _ctx("Agent copied the harvested credentials to the remote host over the tunnel",
                   tier="LIKELY", by_call_id={7: tools_dir}, input_call_ids=[7], linked_call_id=7)
        assert nag.check(ctx) is None


class TestBehaviourWordsAreAssertedWords:
    """The hypothesis gate keys on behaviour words. They are matched as
    words, and only where the finding asserts the behaviour."""

    def test_orphaned_directory_entries_are_not_an_orphan_process(self):
        assert hyp.check(_ctx(
            "All 38 files on the stick sit in $OrphanFiles: the directory entries were "
            "deleted while the data remains recoverable")) is None

    def test_a_denied_exfiltration_needs_no_hypothesis(self):
        assert hyp.check(_ctx(
            "The stick holds personal files only. This is not the exfiltration medium "
            "for the confidential data")) is None

    def test_an_investigation_task_is_not_a_scheduled_task(self):
        assert hyp.check(_ctx("The investigation task on the inbox was answered by two beliefs")) is None

    def test_asserted_behaviour_is_still_gated(self):
        out = hyp.check(_ctx("svchost.exe beacons to 10.0.0.5 every 60 seconds"))
        assert out is not None and out["gate"] == "hypothesize_required"
        out = hyp.check(_ctx("A scheduled task named Updater persists the loader across reboots"))
        assert out is not None
        out = hyp.check(_ctx("Nothing was deleted. The documents were exfiltrated to the stick"))
        assert out is not None

    def test_a_process_in_a_word_is_not_a_process(self):
        assert hyp.check(_ctx("The processing of the images finished at 10:00")) is None


class TestAMediumsOwnListingIsTheTransferRecord:
    """For a removable or optical medium the data's presence on the medium's
    own file system is the transfer record; a folder on the host is not."""

    LISTING = {"type": "tool_call", "cmd": "fls -r -o 32 mnt/stick/ewf/ewf1",
               "stdout_excerpt": ("r/r 2051:\tAuthorized USB (Volume Label Entry)\n"
                                  "d/d 3075:\tSecret Project Data\n"
                                  "+ r/r 5123:\t[secret_project]_design_concept.ppt\n")}
    OTHER = {"type": "tool_call", "cmd": "fls -r -o 32 mnt/stick/ewf/ewf1",
             "stdout_excerpt": "r/r 2051:\tholiday.jpg\nr/r 2052:\tsong.mp3\n"}
    FOLDER = {"type": "tool_call", "cmd": "ls -la mnt/pc/fs/Users/u/Dropbox",
              "stdout_excerpt": "[secret_project]_design_concept.ppt\n"}

    DESC = ("The USB stick (exFAT, serial 4C530012450531101593) was used to exfiltrate the "
            "confidential Secret Project Data folder, among it [secret_project]_design_concept.ppt")

    def test_the_mediums_listing_naming_the_data_passes(self):
        assert ecg.check(_ctx(self.DESC, input_call_ids=[1], by_call_id={1: self.LISTING})) is None

    def test_a_listing_of_other_files_does_not(self):
        out = ecg.check(_ctx(self.DESC, input_call_ids=[1], by_call_id={1: self.OTHER}))
        assert out is not None and out["gate"] == "exfil_channel_grounding"

    def test_a_folder_on_the_host_is_staging_for_a_cloud_channel(self):
        desc = ("[secret_project]_design_concept.ppt was uploaded to the personal Dropbox "
                "account from the sync folder")
        out = ecg.check(_ctx(desc, input_call_ids=[1], by_call_id={1: self.FOLDER}))
        assert out is not None

    def test_optical_media_is_a_channel_and_its_listing_the_record(self):
        desc = ("Exfiltration over physical media: the CD-R burned on the host carries "
                "[secret_project]_technical_review.ppt")
        cdr = {"type": "tool_call", "cmd": "strings -a -n 4 evidence/cd/disc.dd",
               "stdout_excerpt": "UDF Volume\n[secret_project]_technical_review.ppt\n"}
        out = ecg.check(_ctx(desc, supporting_evidence="the disc was found in the bag"))
        assert out is not None and out["gate"] == "exfil_channel_grounding"
        assert ecg.check(_ctx(desc, input_call_ids=[1], by_call_id={1: cdr})) is None


class TestServicesAndDocumentsAreNotPeople:
    """A capitalised token the finding itself spells as a file stem, a domain
    label or a path segment names a thing; only a person-shaped name that is
    none of those is an accusation the named-actor gate must ground."""

    def test_a_document_title_is_not_a_person(self):
        out = nag.check(_ctx(
            "Planning material for the attack is present on the Desktop and was copied to "
            "consumer cloud sync folders. Documents: 'The Manifesto.docx', 'Planning.docx', "
            "'Operation Smoke.pptx'. The same documents appear in Dropbox and Google Drive folders.",
            supporting_evidence="Desktop listing: Planning.docx, The Manifesto.docx"))
        assert out is None

    def test_a_web_service_spelled_as_a_domain_is_not_a_person(self):
        out = nag.check(_ctx(
            "The identity user1@example.test is corroborated in the browser history: Google Docs "
            "(docs.google.com/document with authuser=user1@example.test) and a Google account "
            "checkup. This is the account used to register the services used for exfiltration.",
            supporting_evidence="History: docs.google.com/document/u/0/?authuser=user1@example.test"))
        assert out is None

    def test_a_person_who_is_none_of_those_is_still_gated(self):
        out = nag.check(_ctx("Alice Roe copied the archive to the removable stick",
                             supporting_evidence="fls listing: archive.7z"))
        assert out is not None and out["gate"] == "named_actor_attribution_grounding"
        assert "Alice" in out["error"] or "Roe" in out["error"]

    def test_a_profile_directory_still_names_its_person(self):
        from tools._gates._match import named_things_in_text
        things = named_things_in_text(r"C:\Users\jsmith\Desktop\notes.txt and docs.google.com")
        assert "jsmith" not in things
        assert {"desktop", "notes", "docs", "google", "com"} <= things


class TestABindingToAnAccountOrAThingIsNotAPrincipal:
    """The principal gate grounds a binding of an account to a person. A
    binding to another account, to an artifact noun, to a file, domain or
    path token, or to nobody named is not an attribution."""

    def test_an_account_used_by_an_account_binds_no_person(self):
        out = pag.check(_ctx(
            "The machine is owned and used by local Windows account 'jcloudy'. The user profile "
            "C:\\Users\\jcloudy contains the Desktop, Documents and cloud sync folders. Two online "
            "identities are bound to the browser: user@example.test and user1@example.test.",
            supporting_evidence="Users listing shows jcloudy; Chrome Login Data binds user@example.test"))
        assert out is None

    def test_an_account_used_by_nobody_named_binds_no_person(self):
        assert pag.check(_ctx("The service account was used by the attacker to stage the archive",
                              supporting_evidence="fls: archive.7z")) is None

    def test_an_account_operated_by_a_named_person_is_still_gated(self):
        out = pag.check(_ctx("The account jsmith is operated by Jim Cloudy, who staged the archive",
                             supporting_evidence="fls: archive.7z"))
        assert out is not None and out["gate"] == "principal_attribution_grounding"

    def test_a_session_artifact_still_grounds_it(self):
        out = pag.check(_ctx("The account jsmith is operated by Jim Cloudy",
                             supporting_evidence="Security 4624 LogonType 10 TargetUserName jsmith "
                                                 "IpAddress 10.0.0.5 at 2031-02-04T12:00:00Z"))
        assert out is None
